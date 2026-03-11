# CTTO — Credential Theft Technique Observatory

A modular cybersecurity research framework for studying credential theft techniques, building detection telemetry, and analyzing attacker behavior through realistic honeypot services.

---

## Features

- **3 Honeypot Modules** — Web Login (HTML form), REST API Auth, HTTP Basic Auth
- **Real-Time Dashboard** — Live attack feed, charts, KPI cards, threat distribution
- **Threat Scoring Engine** — Automatic risk scoring (0–100) based on username, user-agent, and header analysis
- **GeoIP Location** — Attacker IP-to-location resolution (free API + optional MaxMind offline DB)
- **Request Fingerprinting** — Browser detection, automation detection, attack tool identification
- **Behavior Analysis** — Pattern analysis across captured credential attempts
- **Export Reports** — Download CSV/JSON from dashboard or CLI
- **Live Terminal Monitor** — Real-time Rich CLI attack feed (`ctto monitor`)
- **Unified Launcher** — Single command to run all services (`ctto run`)

---

## Architecture

```
ctto-framework/
├── ctto.py                  # Main CLI entrypoint
├── config.yaml              # Framework configuration
├── requirements.txt         # Python dependencies
├── core/
│   ├── engine.py            # Core engine (DB + module orchestration)
│   ├── database.py          # SQLAlchemy ORM + SQLite with WAL mode
│   ├── logger.py            # Logging subsystem
│   ├── config_loader.py     # YAML config loader
│   ├── module_loader.py     # Dynamic module discovery
│   ├── live_monitor.py      # Rich Live terminal monitor
│   └── report_exporter.py   # CSV/JSON report exporter
├── modules/
│   ├── auth/
│   │   ├── web_login.py     # Web login form honeypot (port 8080)
│   │   ├── api_auth.py      # REST API auth honeypot (port 8081)
│   │   └── basic_auth.py    # HTTP Basic Auth honeypot (port 8082)
│   ├── fingerprinting/
│   │   ├── request_fingerprint.py  # Browser/automation/tool detection
│   │   └── geoip_lookup.py        # GeoIP resolution (API + MaxMind)
│   └── analysis/
│       ├── behavior_analysis.py    # Credential pattern analysis
│       └── threat_score.py         # Threat scoring engine
├── dashboard/
│   └── web_dashboard.py     # Flask dashboard (port 5000)
├── templates/
│   └── login.html           # Web login honeypot template
├── data/                    # SQLite database (auto-created)
├── logs/                    # Log files
└── scripts/                 # Utility scripts
```

---

## Installation & Setup

### Prerequisites

- **Python 3.10+**
- **pip**
- **git**

### On Linux / WSL (Ubuntu)

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/ctto-framework.git
cd ctto-framework

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create data and logs directories (auto-created on first run, but just in case)
mkdir -p data logs
```

### On Windows (Native)

```powershell
# 1. Clone the repository
git clone https://github.com/<your-username>/ctto-framework.git
cd ctto-framework

# 2. Create virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create data and logs directories
mkdir data, logs
```

### On Windows via WSL

```powershell
# Open WSL
wsl -d Ubuntu

# Then follow the Linux instructions above
```

---

## Running the Framework

### Start Everything (Recommended)

```bash
python3 ctto.py run
```

This launches **all 4 services** in a single process:

| Service          | Port | URL                          |
|-----------------|------|------------------------------|
| Web Login        | 8080 | http://localhost:8080/login   |
| API Auth         | 8081 | http://localhost:8081/        |
| Basic Auth       | 8082 | http://localhost:8082/        |
| Dashboard        | 5000 | http://localhost:5000/        |

### Start Individual Services

```bash
python3 ctto.py serve web-login     # Port 8080
python3 ctto.py serve api-auth      # Port 8081
python3 ctto.py serve basic-auth    # Port 8082
python3 ctto.py serve dashboard     # Port 5000
```

### Other Commands

```bash
# Live terminal attack monitor
python3 ctto.py monitor

# Export attack reports
python3 ctto.py export                    # CSV (default)
python3 ctto.py export --format json      # JSON
python3 ctto.py export --output report.csv # Custom filename

# Analyze captured attacks
python3 ctto.py analyze

# Show loaded modules
python3 ctto.py modules

# Initialize engine only
python3 ctto.py start
```

### Stopping

Press **Ctrl+C** in the terminal running `ctto.py run`.

If ports are stuck from a previous session:

```bash
sudo fuser -k 8080/tcp 8081/tcp 8082/tcp 5000/tcp
```

---

## Dashboard

Open **http://localhost:5000/** after starting the framework.

The dashboard includes:
- **KPI Cards** — Total attacks, average threat score, high/critical threat counts
- **Charts** — Top usernames, top passwords, attack methods, threat score distribution (doughnut)
- **Top Attacker Locations** — GeoIP-resolved location table
- **All Attack Attempts** — Live auto-refreshing table with threat scores, locations, and user-agents
- **Export Buttons** — Download CSV or JSON directly from the dashboard

The dashboard auto-refreshes every 5 seconds — no page reload needed.

---

## Threat Scoring

Each attack is automatically scored (0–100):

| Signal                        | Points |
|------------------------------|--------|
| Default username (admin, root, test...) | +30 |
| curl user-agent              | +20    |
| python-requests user-agent   | +20    |
| sqlmap / nikto / nmap        | +30    |
| hydra / medusa               | +40    |
| Automation fingerprint       | +10    |

Scores are color-coded:
- **Green** (0–29): Low risk
- **Yellow** (30–59): Medium risk
- **Red** (60–79): High risk
- **Dark Red** (80–100): Critical

---

## GeoIP Setup (Optional)

GeoIP works out of the box using the free **ip-api.com** service (no setup required).

For offline/faster lookups, optionally add MaxMind:

```bash
pip install geoip2
# Download GeoLite2-City.mmdb from https://dev.maxmind.com/geoip/geolite2/
# Place it at: data/GeoLite2-City.mmdb
```

---

## Configuration

Edit `config.yaml` to customize ports, module loading, and other settings.

Environment variables:
- `CTTO_DASHBOARD_KEY` — Set to require an API key header for dashboard access (optional)
- `CTTO_SECRET` — Flask secret key for web login sessions

---

## Tech Stack

- **Python 3** — Core language
- **Flask** — Web framework for honeypots and dashboard
- **SQLAlchemy** — ORM with SQLite (WAL mode, busy timeout)
- **Rich** — Terminal UI (banner, tables, live monitor, progress bars)
- **Chart.js** — Dashboard visualizations
- **ip-api.com** — Free GeoIP resolution

---

## License

This project is for **educational and research purposes only**. Do not deploy honeypots on networks without proper authorization.

---

## Author

Built by **Thakor Pavansinh **

