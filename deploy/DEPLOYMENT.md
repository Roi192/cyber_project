# Deploying Website Monitor to the college Linux server

Status: **instructions only - nothing here has been run on the server yet.**

Everything happens inside one directory owned by your own user. No `sudo`, no system
packages, no firewall change, no systemd service, no `chmod 777`.

Assumed target: Ubuntu 20.04, Python 3.8.10, application port 5002, shared machine.

    Windows PC (browser extension) --HTTP--> Gunicorn + Flask :5002 --> SQLite
                                                       |
                                                       +--> VirusTotal (server side)
    Lecturer's PC: only a web browser, opens http://<LINUX-IP>:5002/

## 0. Facts derived from the code

| Item | Value |
|---|---|
| Gunicorn entry point | `app:app` (module `app.py`, variable `app`, run from the project directory) |
| Workers / threads | `--workers 1 --threads 4` (one worker on purpose: SQLite and the reputation back-off state live in the process; threads are safe, each request opens its own connection) |
| Bind | `--bind 0.0.0.0:5002` (`HOST` / `PORT` in `.env` are only used by `python app.py`, not by Gunicorn) |
| Database | created automatically on first start (`data/monitoring.db` inside the project directory), schema and migrations are idempotent |
| Needs the extension? | only computers whose browsing should be monitored. Viewing the dashboard needs a browser only |

## 1. Look around first (read-only)

    python3.8 --version
    python3 --version
    whoami
    pwd
    hostname -I
    date
    ss -ltn 'sport = :5002'
    df -T "$HOME" | tail -1

* `hostname -I` lists the server's IP addresses: this is the `<LINUX-IP>` for the extension.
* `ss -ltn 'sport = :5002'` prints only the header line when port 5002 is free. If a line
  with `LISTEN` appears, choose another port (change `5002` in the commands below and in the
  extension address).
* `df -T` shows the filesystem type. If it says `nfs`, SQLite locking is unreliable: set
  `DATABASE_PATH` in `.env` to a path on a local disk (an absolute path is used as is).
* `date` should match the Windows clock and time zone. See "Time zone" below.

## 2. Copy and unpack

Build the archive on Windows (`python deploy/build_package.py`, it prints the SHA-256), copy it to
your home directory on the server (`scp` or your usual file transfer), then on the server:

    cd ~
    sha256sum website-monitor-deploy-*.tar.gz
    tar -xzf website-monitor-deploy-*.tar.gz
    cd website-monitor
    sha256sum -c SHA256SUMS --quiet && echo files-intact

Compare the first hash with the one printed on Windows. The archive contains no database, no
`.env`, no keys and no virtualenv.

## 3. Python environment (inside the project directory)

Option A, standard `venv` + pip:

    python3.8 -m venv venv
    source venv/bin/activate
    python -m pip install -r requirements.txt
    python -m pip check

If `python3.8 -m venv` fails with "ensurepip is not available" (it needs an admin-installed
package), use option B instead. If pip complains about an old version, run
`python -m pip install --upgrade pip` (this only changes the venv).

Option B, uv (no admin rights needed):

    uv venv venv --python 3.8
    source venv/bin/activate
    uv pip install -r requirements.txt

Check: `python --version` should print Python 3.8.x and `which python` should point inside
`~/website-monitor/venv`.

## 4. Configuration (`.env`, never committed, never printed)

    cp .env.example .env
    chmod 600 .env
    KEY=$(python -c "import secrets; print(secrets.token_hex(24))")
    sed -i "s/^API_KEY=.*/API_KEY=$KEY/" .env
    unset KEY
    SK=$(python -c "import secrets; print(secrets.token_hex(24))")
    sed -i "s/^SECRET_KEY=.*/SECRET_KEY=$SK/" .env
    unset SK
    nano .env

In `nano`, paste the VirusTotal key after `VT_API_KEY=` (no spaces, no quotes), then Ctrl+O,
Enter, Ctrl+X. Typing it into `nano` keeps it out of the shell history. You can skip it:
the monitor then stores every visit and shows them as Not checked / Limited visibility.

When you are ready to type the API key into the extension, show **only that value**:

    grep '^API_KEY=' .env | cut -d= -f2

(Run `clear` afterwards.) The same value goes into every extension's options.

### Environment variables

| Variable | Needed? | Default | Meaning |
|---|---|---|---|
| `API_KEY` | **required for network use** | empty = DEV MODE | shared key the extensions send as `X-Api-Key`. Empty means anybody can upload, and the dashboard shows a development-mode warning. Use 16+ random characters |
| `VT_API_KEY` | optional | empty | VirusTotal key. Absent, rate limited (HTTP 429) or failing: visits are still stored, shown as Not checked, and the status becomes Limited visibility |
| `DATABASE_PATH` | optional | `data/monitoring.db` | relative paths are inside the project directory, absolute paths are used as given. Missing directories are created. The running user must be able to write there |
| `SECRET_KEY` | optional | `dev-only-change-me` | currently unused (the app has no sessions); set it anyway |
| `HOST`, `PORT` | optional | `0.0.0.0`, `5002` | only for `python app.py`. With Gunicorn use `--bind` |
| `RETENTION_DAYS` | optional | `30` | visits older than this are deleted when the dashboard is opened. `0` keeps everything |
| `REPUTATION_CACHE_HOURS` | optional | `24` | how long a Safe verdict is cached (suspicious/dangerous 6 h, not-checked 30 min are fixed) |
| `TZ` | optional, OS level | server default | time zone of the process, see below |

No `FLASK_*` variable is read.

## 5. Pre-flight check (prints OK/WARN/FAIL, never a secret)

    python deploy/check_env.py

Fix every `FAIL` before starting. A `WARN` about `VT_API_KEY` is acceptable for a first run.
Optional, safe (uses temporary databases only, no real VirusTotal calls):

    python -m unittest discover -s tests

## 6. First start in the foreground

    gunicorn --workers 1 --threads 4 --bind 0.0.0.0:5002 --access-logfile - app:app

Leave it running and open a second terminal on the server (`cd ~/website-monitor`,
`source venv/bin/activate`). Stop it later with Ctrl+C.

## 7. Verify on the server itself

    curl -s http://127.0.0.1:5002/api/status | head -c 400
    curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5002/
    curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5002/api/ping

Expected: JSON starting with `{"dev_mode":false,`; `200`; and `401` for the last one (no key,
proving authentication is on). To check that the key works without putting it on the command line
(other users can see command lines on a shared server):

    KEY=$(grep '^API_KEY=' .env | cut -d= -f2)
    printf 'X-Api-Key: %s\n' "$KEY" | curl -s -o /dev/null -w "%{http_code}\n" -H @- http://127.0.0.1:5002/api/ping
    unset KEY

Expected `200`. Do not print `.env`.

## 8. Connect from outside

1. From the Windows PC, open `http://<LINUX-IP>:5002/api/status` in a browser. JSON means the
   network path works. If it does not load while step 7 worked, the port is blocked by a
   firewall between the machines. Do not change anything on the server: ask the administrator
   to allow TCP 5002 from the lab network, or choose a port that is already allowed.
2. Install the extension on that Windows PC (`browser_extension` folder, "Load unpacked").
3. Extension options: server address `http://<LINUX-IP>:5002`, a computer name, a user name,
   the API key from step 4. Press **Test connection** (expect "Connected successfully"), then
   **Save** and allow the browser's one-time permission prompt for that address.
4. Browse a few ordinary sites. They appear on `http://<LINUX-IP>:5002/` within about 7 seconds.
5. The lecturer opens `http://<LINUX-IP>:5002/` in any browser. No extension is needed there
   unless that computer's own browsing should be monitored.

## 9. Run in the background without systemd

    mkdir -p logs
    gunicorn --workers 1 --threads 4 --bind 0.0.0.0:5002 \
      --daemon --pid gunicorn.pid \
      --access-logfile logs/access.log --error-logfile logs/error.log app:app

    ps -u "$USER" -o pid,etime,args | grep '[g]unicorn'
    tail -n 20 logs/error.log
    kill "$(cat gunicorn.pid)"

The process does not survive a server reboot: start it again with the same command. Logs contain
request lines only, never the API key (it travels in a header).

## 10. Time zone

Visit times come from each endpoint's clock, while "today", "online" and "last seen" use the
server's clock. If `date` on the server shows a different zone from the Windows PCs, start Gunicorn
with the zone of the PCs:

    TZ=Asia/Jerusalem gunicorn --workers 1 --threads 4 --bind 0.0.0.0:5002 app:app

(use the same `TZ=` prefix in the background command). Set it before the first start.

## 11. Troubleshooting

| Symptom | Cause / action |
|---|---|
| `ModuleNotFoundError` | the venv is not active: `source venv/bin/activate` |
| `Address already in use` | port 5002 is taken: choose another port in `--bind` and in the extension address |
| `Permission denied` on `data` | the directory is not yours: unpack in your home directory |
| `database is locked` | the database is on a network filesystem: set `DATABASE_PATH` to a local disk path |
| Extension says "Authentication failed" | the key in the extension differs from `API_KEY` in `.env` |
| Extension says "Cannot reach server" | wrong IP/port, server not running, or a firewall in between |
| Dashboard says "Development mode" | `API_KEY` is empty or `.env` was not read: run `python deploy/check_env.py` |

## 12. Security notes for this lab deployment

* **HTTP is acceptable only on the isolated college lab network for this demonstration.** The API key
  and the visited domains cross the network unencrypted. A real small-business deployment **requires
  HTTPS** (a reverse proxy with a certificate); the extension already accepts `https://` addresses.
* **The dashboard has no login.** Anyone who can reach port 5002 can read it and use the Archive and
  "Mark as handled" buttons. `API_KEY` only protects uploads.
* The API key is kept in each browser's extension storage: practical, not hardware-protected.
* `.env` is mode 600, owned by you, and is not part of the archive.

## 13. Remove everything

    kill "$(cat gunicorn.pid)"
    cd ~
    rm -rf ~/website-monitor ~/website-monitor-deploy-*.tar.gz*
