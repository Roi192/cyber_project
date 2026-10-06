# ==================================================
# STEP 24A PILOT: register the Native Messaging Host
# ==================================================
#
# Run this yourself, manually, AFTER loading the unpacked extension in
# chrome://extensions and edge://extensions (Developer Mode -> "Load
# unpacked" -> select the browser_extension folder) and copying its
# generated Extension ID from that page. This script is NOT executed
# automatically by Claude - it changes real per-user registry state
# (HKCU, not HKLM) on this machine, which is why it is left for you to
# run deliberately as part of the controlled pilot.
#
# Usage (ONE browser per run, by design - the pilot proceeds Chrome
# first, Edge only after Chrome succeeds):
#   powershell -ExecutionPolicy Bypass -File install_native_host.ps1 -Browser chrome -ExtensionId <id-from-chrome-extensions-page>
#   powershell -ExecutionPolicy Bypass -File install_native_host.ps1 -Browser edge   -ExtensionId <id-from-edge-extensions-page>
#
# What it does:
#   1. Writes a real native-host manifest JSON (from the template in
#      this folder) with the resolved run_native_host.bat path and your
#      Extension ID filled in - BOM-less UTF-8/ASCII (see note below).
#   2. Registers that manifest under exactly ONE of:
#      HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.cyberproject.browser_monitor
#      HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.cyberproject.browser_monitor
#      depending on -Browser (current-user only - no admin rights
#      required, nothing written under HKLM, no other registry key
#      touched, and the OTHER browser's key is left completely alone).
#
# To undo: delete the one registry key above (Remove-Item) and delete
# the generated manifest JSON next to this script.

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("chrome", "edge")]
    [string]$Browser,

    [Parameter(Mandatory = $true)]
    [string]$ExtensionId
)

$ErrorActionPreference = "Stop"

# Chrome/Edge extension ids are always exactly 32 lowercase characters
# from the range a-p (the Chromium "mpdecimal"-style base16-of-a-p
# alphabet) - this is well documented and stable across Chrome/Edge.
# Not a security check (HKCU-only, current user) - just catches a
# copy/paste mistake before it is silently baked into the registry.
if ($ExtensionId -notmatch '^[a-p]{32}$') {
    throw "ExtensionId '$ExtensionId' does not look like a real Chrome/Edge extension id (expected exactly 32 lowercase letters a-p). Copy it again from chrome://extensions / edge://extensions."
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$templatePath = Join-Path $scriptDir "com.cyberproject.browser_monitor.template.json"

# Step 24A.2 fix: a SEPARATE manifest file per browser, not one shared
# file. Chrome and Edge each generate their OWN extension id for the
# same unpacked folder, so a single shared manifest's allowed_origins
# would be silently overwritten the moment the second browser is
# registered - installing Edge later would break Chrome's entry (and
# vice versa) without any error or warning. Keeping them in separate
# files means each browser's registry key points to its own,
# independent allowed_origins - installing one never touches the other.
$manifestPath = Join-Path $scriptDir "com.cyberproject.browser_monitor.$Browser.json"
$batPath = Join-Path $scriptDir "run_native_host.bat"

if (-not (Test-Path $templatePath)) {
    throw "Template manifest not found: $templatePath"
}

if (-not (Test-Path $batPath)) {
    throw "run_native_host.bat not found: $batPath"
}

$batPathEscaped = $batPath.Replace('\', '\\')

$content = Get-Content $templatePath -Raw
$content = $content.Replace('__RUN_NATIVE_HOST_BAT_PATH__', $batPathEscaped)
$content = $content.Replace('__EXTENSION_ID__', $ExtensionId)

# Deliberately NOT `Set-Content -Encoding UTF8` - on Windows PowerShell
# 5.1 that writes a UTF-8 BOM (confirmed: EF BB BF), and Chrome's native
# messaging host manifest JSON parser is not guaranteed to tolerate a
# BOM (documented real-world cause of "Specified native messaging host
# not found" failures). The manifest content here is pure ASCII, so
# writing plain ASCII bytes sidesteps the question entirely.
[System.IO.File]::WriteAllText($manifestPath, $content, [System.Text.Encoding]::ASCII)

Write-Host "Wrote manifest: $manifestPath"

$browserKey = if ($Browser -eq "chrome") {
    "HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.cyberproject.browser_monitor"
} else {
    "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.cyberproject.browser_monitor"
}

New-Item -Path $browserKey -Force | Out-Null
Set-ItemProperty -Path $browserKey -Name "(Default)" -Value $manifestPath
Write-Host "Registered: $browserKey -> $manifestPath"

Write-Host ""
Write-Host "Done. Completely close every $Browser window (not just the tab) before testing - native messaging host registration is only read at browser startup."
