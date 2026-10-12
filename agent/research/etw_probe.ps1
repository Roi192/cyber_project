<#
  Website Monitor - ETW feasibility probe (research tool, NOT part of the agent, never shipped).

  STATUS: audited and rewritten in Phase 5.3 preparation. Verified without elevation only: it parses, and it
  refuses to run unless the shell is elevated. The traced part has NOT been run yet.

  QUESTION IT ANSWERS: can Windows ETW move us from "chrome.exe -> IP" toward "chrome.exe -> domain -> IP" with no
  browser extension? It traces two providers into ONE temporary session:
    Microsoft-Windows-Kernel-Network  TCP/UDP connect, send, receive: process id, destination address, port, size
                                      (this is the one that can also show UDP/QUIC and very short connections)
    Microsoft-Windows-DNS-Client      DNS queries made through the Windows resolver (query name, result)
  Chrome and Edge use their own DNS client by default, so DNS-Client may show NOTHING for them. That is part of the
  answer, and the probe reports it instead of hiding it.

  WHY ADMINISTRATOR: Windows lets only administrators (or "Performance Log Users") start an ETW session.

  WHAT IT CHANGES: nothing permanent. One temporary session (logman ... -ets, never stored), one trace file and one CSV
  in %TEMP%. On normal end, error or Ctrl+C the session is stopped and both files are deleted. It installs nothing,
  changes no firewall, browser, network or security setting, intercepts nothing, and the providers carry no packet
  payloads and no HTTPS content (addresses, ports, sizes, process ids and DNS names only). Nothing is sent anywhere.

  USAGE (elevated PowerShell, from the project folder):
      powershell -NoProfile -ExecutionPolicy Bypass -File .\agent\research\etw_probe.ps1 -Seconds 90
  During the run: the probe prints a clock time to open domain A, and another to open domain B.
#>
param([int]$Seconds = 90)

$ErrorActionPreference = "Stop"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This probe needs an ELEVATED PowerShell (an ETW session cannot be started without it). Nothing was done."
    exit 2
}
if ($Seconds -lt 30 -or $Seconds -gt 300) { Write-Host "-Seconds must be between 30 and 300."; exit 2 }

$session = "WMAProbe"
$etl = Join-Path $env:TEMP "wma_probe.etl"
$csv = Join-Path $env:TEMP "wma_probe.csv"
$names = @{}

function Stop-ProbeSession { logman stop $session -ets 2>$null | Out-Null }
function Remember-Processes {
    Get-Process | ForEach-Object { $names[[int]$_.Id] = $_.ProcessName }       # short-lived programs are caught by repeating this
}
function Stamp { param($text) Write-Host ("[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $text) }

try {
    Stop-ProbeSession                                   # clears a stale session left by an earlier crashed run
    Remove-Item $etl, $csv -ErrorAction SilentlyContinue
    logman create trace $session -p "Microsoft-Windows-Kernel-Network" 0x30 0xff -o $etl -ets | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "could not start the trace session (logman exit code $LASTEXITCODE)" }
    logman update trace $session -p "Microsoft-Windows-DNS-Client" 0xFFFFFFFFFFFFFFFF 0xff -ets | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "could not add the DNS-Client provider (logman exit code $LASTEXITCODE)" }

    $half = [int]($Seconds / 2)
    Stamp "TRACING STARTED. Browser extension must be removed/disabled. Use DEFAULT Chrome."
    Stamp "NOW: open harmless domain A in Chrome (type it in the address bar)."
    for ($i = 1; $i -le $Seconds; $i++) {
        Remember-Processes
        if ($i -eq $half) { Stamp "NOW: navigate the same tab to harmless domain B." }
        Start-Sleep -Seconds 1
    }
    Stamp "STOP browsing. Stopping the trace and reading it ..."
    Stop-ProbeSession

    tracerpt $etl -o $csv -of CSV -y 2>$null | Out-Null
    if (-not (Test-Path $csv)) { throw "tracerpt produced no output" }
    $rows = Import-Csv $csv
    Write-Host ("events recorded: " + @($rows).Count)
    Write-Host ("columns: " + (($rows | Select-Object -First 1).PSObject.Properties.Name -join ", "))

    function Process-Name($row) { $p = [int]$row.PID; if ($names.ContainsKey($p)) { $names[$p] } else { "pid$p" } }
    function Event-Time($row) {
        try { return [DateTime]::FromFileTime([int64]$row.'Clock-Time').ToString("HH:mm:ss.fff") } catch { return [string]$row.'Clock-Time' }
    }
    $dns = @($rows | Where-Object { $_.'Event Name' -match 'DNS' -or $_.'User Data' -match 'QueryName' })
    $net = @($rows | Where-Object { $_.'User Data' -match 'daddr' })
    Write-Host ""
    Write-Host ("=== DNS-Client events: {0}   Kernel-Network events with a destination: {1}" -f $dns.Count, $net.Count)

    Write-Host ""
    Write-Host "=== DNS queries seen by the Windows resolver (who asked, what name). Empty for Chrome = it bypasses the Windows resolver."
    $dns | ForEach-Object {
        $name = ""; if ($_.'User Data' -match 'QueryName\W+([^\s,;"<>{}]+)') { $name = $Matches[1] }
        [pscustomobject]@{ Time = (Event-Time $_); Process = (Process-Name $_); Query = $name }
    } | Where-Object { $_.Query } | Sort-Object Time -Unique | Select-Object -First 60 | Format-Table -AutoSize | Out-String | Write-Host

    Write-Host "=== chrome / msedge destinations: first time each address was seen (TCP and UDP, with port when present)"
    $timeline = $net | Where-Object { (Process-Name $_) -match '^(chrome|msedge)$' } | ForEach-Object {
        $addr = ""; $port = ""
        if ($_.'User Data' -match 'daddr\W+([0-9a-fA-F:\.]+)') { $addr = $Matches[1] }
        if ($_.'User Data' -match 'dport\W+(\d+)') { $port = $Matches[1] }
        [pscustomobject]@{ Time = (Event-Time $_); Process = (Process-Name $_); PID = $_.PID; Event = $_.'Event Name'; Address = $addr; Port = $port }
    }
    $timeline | Sort-Object Address -Unique | Sort-Object Time | Select-Object -First 80 | Format-Table -AutoSize | Out-String | Write-Host
    Write-Host ("distinct chrome/msedge destination addresses: " + @($timeline | Select-Object -ExpandProperty Address -Unique).Count)
    Write-Host ("UDP/QUIC-looking events to port 443 from chrome/msedge: " + @($timeline | Where-Object { $_.Event -match 'UDP' -and $_.Port -eq '443' }).Count)

    Write-Host ""
    Write-Host "=== three raw lines of each kind, so the field names can be checked by eye"
    $dns | Select-Object -First 3 | ForEach-Object { Write-Host ("DNS raw: " + $_.'User Data') }
    $net | Where-Object { (Process-Name $_) -match '^(chrome|msedge)$' } | Select-Object -First 3 | ForEach-Object { Write-Host ("NET raw: " + $_.'User Data') }
}
finally {
    Stop-ProbeSession
    Remove-Item $etl, $csv -ErrorAction SilentlyContinue
    Write-Host "Session stopped; temporary files removed."
}
