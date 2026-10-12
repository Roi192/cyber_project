# Local Ubuntu 20.04 compatibility test of the college installation (Windows PowerShell). Needs Docker Desktop running. Nothing is installed on your PC by this script.
#
#   cd C:\Users\Moshe\cyber_project_college          (the folder that holds cyber_project\ and docker_test\)
#   powershell -ExecutionPolicy Bypass -File docker_test\run_college_test.ps1            # build + smoke + exact `python app.py` run
#   powershell -ExecutionPolicy Bypass -File docker_test\run_college_test.ps1 -Cleanup   # remove the container, the image and the build cache of this test
param([switch]$Cleanup)
$ErrorActionPreference = "Stop"
$compose = "docker_test/docker-compose.college-test.yml"
Set-Location (Split-Path -Parent $PSScriptRoot)

if ($Cleanup) {
    docker compose -f $compose down --rmi local --volumes --remove-orphans
    docker image rm wm-college-test:ubuntu2004 2>$null
    Write-Host "Cleaned: container, image and volumes of the college test are removed."
    exit 0
}

docker version --format "Docker engine {{.Server.Version}} on {{.Server.Os}}/{{.Server.Arch}}"
Write-Host "`n== 1. Build: Ubuntu 20.04, python3 -m venv venv, pip install -r requirements.txt, pip check (the college sequence, as user team2)"
docker compose -f $compose build
docker run --rm wm-college-test:ubuntu2004 bash -c "cat /etc/os-release | head -2; python3 --version; id; source /home/team2/cyber_project/venv/bin/activate && python --version && pip list --format=freeze"

Write-Host "`n== 2. Independent end-to-end check with NO network (first start, setup, login, pages, demo, restart, leaks)"
docker compose -f $compose run --rm smoke
$smoke = $LASTEXITCODE

Write-Host "`n== 3. The exact last college command: python app.py (published on 127.0.0.1:5396 of this PC only (container port 5002))"
docker compose -f $compose up -d college-test
$healthy = $false
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Seconds 2
    $code = (curl.exe -s -o NUL -w "%{http_code}" http://127.0.0.1:5396/login)
    if ($code -eq "200") { $healthy = $true; break }
}
Write-Host ("login page HTTP " + $code)
docker compose -f $compose logs --no-color college-test
Write-Host "`n== 4. Graceful shutdown (SIGTERM from docker stop)"
docker compose -f $compose stop college-test
docker compose -f $compose logs --no-color --tail 3 college-test
docker compose -f $compose down

if ($smoke -ne 0 -or -not $healthy) { Write-Host "`nRESULT: FAILED (smoke exit $smoke, healthy $healthy)"; exit 1 }
Write-Host "`nRESULT: PASSED (smoke exit 0, app answered on host port 5396 (container 5002), stopped cleanly). Clean up with:  -Cleanup"
