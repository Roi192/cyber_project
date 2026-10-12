# Docker compatibility test kit (Phase F3.30) - Ubuntu 20.04, Python 3.8.10, user team2

Docker is **only a local test bench**. The college runs the application directly (`python app.py`), without Docker.

## Status of this kit
**Written and statically checked, NOT YET EXECUTED**: Docker was not installed on the development PC when this kit was prepared, and installing it needs your approval. Until you run it
(below) the Ubuntu 20.04 results are unproven. What *was* executed (Windows, Python 3.8.20 and 3.14): the same installation sequence with a fresh venv, `pip check`, the full test
suite and the independent end-to-end verifier (`verify_college_package.py`, 70 checks).

## Run it (when Docker Desktop is running)
```powershell
cd C:\Users\Moshe\cyber_project_college                   # holds cyber_project\ and docker_test\
powershell -ExecutionPolicy Bypass -File docker_test\run_college_test.ps1
```
Linux/macOS/Git Bash: `bash docker_test/run_college_test.sh`. Equivalent manual commands:
```
docker compose -f docker_test/docker-compose.college-test.yml build
docker compose -f docker_test/docker-compose.college-test.yml run --rm smoke
docker compose -f docker_test/docker-compose.college-test.yml up        # python app.py; http://127.0.0.1:5396/ (container port 5002)
```
**Cleanup:** `powershell -File docker_test\run_college_test.ps1 -Cleanup` (or `bash docker_test/run_college_test.sh --cleanup`), i.e.
`docker compose -f docker_test/docker-compose.college-test.yml down --rmi local --volumes --remove-orphans`.

## What it proves
1. **Build** (`Dockerfile.college-test`): `ubuntu:20.04` + `python3 python3-venv` (3.8.10), user `team2` (uid 1000, no root, `no-new-privileges`, all capabilities dropped), then the college
   sequence verbatim: `python3 -m venv venv`, `source venv/bin/activate`, `pip install -r requirements.txt`, `python -m pip check`. TLS verification is never disabled.
2. **Smoke** (`run --rm smoke`, **no network at all**): `verify_college_package.py` runs a pristine copy of the package as `python app.py` with this venv: no `.env`/database to begin with,
   setup code, first administrator, sign-in, every page, static files, a simulated browsing event through the sensor API, `python demo.py` (all seven providers simulated),
   second copy refused, graceful stop on SIGTERM, restart keeps data, a private `.env` honoured, **file mode 600 of `.env`** (the POSIX check Windows cannot do), secret and traceback scan.
3. **Exact start** (`up`): the container's command is `source venv/bin/activate && exec python app.py`; the script checks the login page on host port 5396 (container port 5002, so it never collides with a production monitor on 5002) and the clean shutdown message.

## What stays out of the image
No `.env`, no API key, no database, no backup, no log, no `venv`, no `ca-bundle.pem`/Windows certificate, no tests/Agent/extension (`dockerignore.college-test` -> copy it as `.dockerignore` into the
build-context folder; the staging script already does). Providers stay unconfigured unless you pass `--env-file`/`env_file` with your own `provider-test.env` at run time
(authorised live test only; APIVoid has almost no credits left).

## Differences from the real college server (be aware)
* The container is a minimal Ubuntu 20.04; the college server has other software, users, a shared filesystem (NFS is a known SQLite hazard: if the home directory is on NFS, set
  `DATABASE_PATH` to a local disk), a proxy/firewall that may re-sign HTTPS or block PyPI and the providers, and Guacamole in front.
* `HOST=0.0.0.0` inside the container (needed for the published port) generates an API key at first start; the college default is `HOST=127.0.0.1`.
* Docker has direct internet or none (`smoke` has none); the college network policy is unknown until you try `pip install` there.
* Your PC's antivirus (Avast) certificate does not exist in the container; that is intentional.
