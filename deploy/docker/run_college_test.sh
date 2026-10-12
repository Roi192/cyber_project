#!/usr/bin/env bash
# Local Ubuntu 20.04 compatibility test of the college installation (Linux/macOS/Git Bash). Needs Docker running. Nothing is installed on your machine by this script.
#
#   cd <the folder that holds cyber_project/ and docker_test/>
#   bash docker_test/run_college_test.sh              # build + smoke + exact `python app.py` run
#   bash docker_test/run_college_test.sh --cleanup    # remove the container, the image and the volumes of this test
set -u
COMPOSE="docker_test/docker-compose.college-test.yml"
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

if [ "${1:-}" = "--cleanup" ]; then
    docker compose -f "$COMPOSE" down --rmi local --volumes --remove-orphans
    docker image rm wm-college-test:ubuntu2004 2>/dev/null
    echo "Cleaned: container, image and volumes of the college test are removed."
    exit 0
fi

docker version --format 'Docker engine {{.Server.Version}} on {{.Server.Os}}/{{.Server.Arch}}' || exit 2
echo; echo "== 1. Build: Ubuntu 20.04, python3 -m venv venv, pip install -r requirements.txt, pip check (as user team2)"
docker compose -f "$COMPOSE" build || exit 1
docker run --rm wm-college-test:ubuntu2004 bash -c 'head -2 /etc/os-release; python3 --version; id; source /home/team2/cyber_project/venv/bin/activate && python --version && pip list --format=freeze'

echo; echo "== 2. Independent end-to-end check with NO network"
docker compose -f "$COMPOSE" run --rm smoke
smoke=$?

echo; echo "== 3. The exact last college command: python app.py (published on 127.0.0.1:5396 only (container port 5002))"
docker compose -f "$COMPOSE" up -d college-test
healthy=1
for _ in $(seq 1 40); do
    sleep 2
    code="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5396/login)"
    [ "$code" = "200" ] && { healthy=0; break; }
done
echo "login page HTTP $code"
docker compose -f "$COMPOSE" logs --no-color college-test
echo; echo "== 4. Graceful shutdown (SIGTERM from docker stop)"
docker compose -f "$COMPOSE" stop college-test
docker compose -f "$COMPOSE" logs --no-color --tail 3 college-test
docker compose -f "$COMPOSE" down

if [ "$smoke" -ne 0 ] || [ "$healthy" -ne 0 ]; then echo; echo "RESULT: FAILED (smoke exit $smoke, health $healthy)"; exit 1; fi
echo; echo "RESULT: PASSED (smoke exit 0, app answered on host port 5396 (container 5002), stopped cleanly). Clean up with: --cleanup"
