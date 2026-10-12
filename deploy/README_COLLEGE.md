# Website Monitor (college edition)

A small web application that records which websites the monitored computers visit, checks each one against **seven threat-intelligence sources**, explains the evidence and
the risk, raises alerts, and compares the running alert policy with a proposed one (Shadow Mode).

## Start it (Linux, Python 3.8, no root)

```bash
cd /home/team2/cyber_project
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

That is all. On the first start `python app.py` by itself:

* creates `.env` if it is missing (new random `SECRET_KEY` and `API_KEY`, mode 600; or uses your private `.env`, see below);
* creates the SQLite database `data/monitoring.db` if it is missing, or keeps the existing one untouched;
* prints a start-up report: address, database, alert policy and the state of the seven sources;
* prints a **one-time setup code**. Open `http://127.0.0.1:5002/setup` in a browser on the server (or through an SSH tunnel), type the code, and choose the administrator's
  user name and a password of at least 12 characters. That page disappears for good once the administrator exists (nobody else can create one).

Then sign in at `http://127.0.0.1:5002/login`. Stop the server with **Ctrl+C**. Start it again later with `source venv/bin/activate` and `python app.py`: the data and the
administrator are kept. Starting a second copy while one runs is refused with a clear message.

Reaching it: the server listens on `127.0.0.1:5002`, i.e. on the college server itself. Use a browser on the server's desktop (Guacamole), or from your own PC
`ssh -L 5002:127.0.0.1:5002 team2@<server>` and then `http://127.0.0.1:5002/`. The Guacamole address is **not** the monitor's address. To let other computers connect set
`HOST=0.0.0.0` in `.env` (the `API_KEY` then protects the sensor routes) and restart.

## Your private `.env` (the seven providers' keys)

The keys are **not** in this folder and never in Git. To use them at college, copy your private file once, from your PC, **before the first start**:

```bash
scp college.env team2@<server>:/home/team2/cyber_project/.env      # then, on the server:  chmod 600 /home/team2/cyber_project/.env
```

Transfer it over SSH/SCP (encrypted), or inside a password-protected archive (`7z a -p -mhe=on`), never in an ordinary ZIP or by e-mail/chat. The app tightens a `.env` that other
users could read to mode 600 by itself. Without the file the monitor still runs: the sources simply show **no key** / **unavailable** and nothing is called safe.
Never copy a Windows-only line such as `REQUESTS_CA_BUNDLE` to Linux.

## No internet, or PyPI blocked?

`pip install` needs HTTPS access to PyPI. If the college blocks it, build a wheel folder on a PC with internet:
`pip download -r requirements.txt -d wheelhouse --only-binary=:all: --python-version 3.8 --implementation cp --abi cp38 --platform manylinux2014_x86_64 --platform any`, copy `wheelhouse/` next to `requirements.txt` and run
`pip install --no-index --find-links wheelhouse -r requirements.txt`. `app.py` cannot fix a blocked network.

## Where do the events come from?

The server only **receives** events; it does not watch anything by itself. Real monitoring needs a sensor that posts to it:

* the **browser extension** (`/api/web-events`, `/api/heartbeat`, ...) and/or the **Windows agent** (`/api/network-events`), both from the full project, with this server's address and the `API_KEY` from `.env`;
* or, for a test or a presentation without sensors, one `curl` per visit (replace `KEY` with the `API_KEY` line of `.env`; the browsing data then appears under *Browsing* and *Computers*):

```bash
curl -s -X POST http://127.0.0.1:5002/api/web-events -H "Content-Type: application/json" -H "X-Api-Key: KEY"   -d '{"endpoint_uid":"demo-pc-1","computer_name":"DEMO-PC","browser":"Chrome","domain":"example.org","url":"https://example.org/","timestamp":"'"$(date +%Y-%m-%dT%H:%M:%S)"'"}'
```

* or the optional **offline demonstration** add-on (`cyber_project_demo_addon.tar.gz`, three files, delivered separately): a simulated computer, a clearly labelled SIMULATED
  malicious site, a provider outage, all seven provider panels and Shadow Mode, with no key and no network. Unpack it in this folder and run `python demo.py`.

## What is in the folder

| Path | Purpose |
|---|---|
| `app.py` | the entry point: routes, dashboard, monitoring API, start-up |
| `bootstrap.py`, `config.py`, `database.py`, `auth.py`, `validation.py` | first-run `.env`, settings, SQLite schema and queries, administrator sign-in and setup, input checks |
| `analytics.py`, `overview.py`, `devices.py` | dashboard figures, wording, computers/devices |
| `services/` | the seven providers (`reputation.py`), evidence, risk, alert policy, Shadow Mode, explanations |
| `templates/`, `static/` | every page, stylesheet and script |
| `manage_admin.py` | optional: reset a password (`python manage_admin.py set-password NAME`) |
| `requirements.txt` | the one dependency list |
| `.env.example` | the settings template |

The three newest sources (APIVoid, MetaDefender Cloud, AbuseIPDB) are **observation only**: shown and stored, never part of a verdict, a risk score or an alert.
The alert policy is `SEVERITY_POLICY=legacy`.
