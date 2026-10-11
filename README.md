# Zyncle Port Scanner
<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=26&pause=1000&color=00F7FF&center=true&vCenter=true&width=900&lines=Unified+Vulnerability+Scan+Workflow;Port+Discovery+%7C+Service+Fingerprinting;CVE+Correlation+%7C+Risk+Scoring;SOC-Style+Web+Dashboard;Detect.+Analyze.+Protect." />


![Backend](https://img.shields.io/badge/backend-FastAPI-009688?logo=fastapi&logoColor=white)
![Frontend](https://img.shields.io/badge/frontend-React%2019%20%2B%20TypeScript-3178C6?logo=react&logoColor=white)
![Build tool](https://img.shields.io/badge/build-Vite%208-646CFF?logo=vite&logoColor=white)
![Database](https://img.shields.io/badge/database-PostgreSQL-4169E1?logo=postgresql&logoColor=white)
![Python](https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows%20(PowerShell)-0078D6)
![API version](https://img.shields.io/badge/API%20version-0.1.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)

[Overview](#overview) · [Features](#key-features) · [Architecture](#system-architecture) · [Setup](#installation-and-setup) · [API](#api-documentation) · [Testing](#testing-and-validation) · [Security](#security-considerations)

</div>

> **Authorized use only.** This tool actively scans networks and hosts. Scan only systems you own or have explicit written permission to assess. See [Security considerations](#security-considerations).

---

## Overview

Zyncle Port Scanner is a web application that orchestrates established open-source scanners behind a single REST API. For a given target it:

1. discovers open ports (**Naabu**),
2. identifies services and versions (**Nmap**),
3. correlates detected versions with published CVEs (**NVD API**),
4. runs template-based checks (**Nuclei**),
5. optionally adds a **Greenbone/OpenVAS** assessment.

Results are normalized, risk-classified, stored in PostgreSQL and explored through a React dashboard. The project orchestrates existing tools; it does not implement its own scanning engine.

Prepared as an internship project submission.

## Problem statement and objectives

Port discovery, service detection and vulnerability checks are usually run as separate tools with different output formats, which makes results hard to compare and track over time.

**Objectives**

- Run the tools as one repeatable workflow behind a simple API.
- Normalize output into a single, persisted data model (scan → host → port → service → finding).
- Apply a consistent, explainable risk classification.
- Present results in a dashboard with history and export.

## Key features

- 🔎 **Two port profiles**: `common` (ports 1–1000) and `full` (1–65535).
- 🧩 **Service and version detection** with CPE extraction (Nmap `-sV`).
- 🛡️ **NVD correlation**: CPE and version are matched to CVEs with version-range applicability filtering; CVSS score, CWE IDs and CVSS vector are stored.
- 🧪 **Nuclei template detection** (tags `vuln,cve`, severities low to critical).
- 🔌 **Optional Greenbone/OpenVAS integration** (disabled by default).
- ⚖️ **Deterministic risk classification** (CVSS thresholds) with the reason stored per finding.
- 🗄️ **Persistent history** in PostgreSQL, managed with Alembic migrations.
- 📊 **Dashboard** with seven views, live status polling (every 3 s), severity filtering, history filtering and **JSON / CSV / print-to-PDF export**.

## Application screenshots

| View | Shows |
|---|---|
| Dashboard | Summary of recent scans (totals, open ports, findings) |
| New Scan | Target, port profile, vulnerability profile |
| Current Scan | Live status, scan pipeline, results |
| Scan History | Past scans, filterable by status and profile |
| Vulnerabilities | Findings with severity distribution and filter |
| Assets | Hosts, open ports and services |
| Settings | API connection and scanner pipeline overview |

<!--
SCREENSHOT PLACEHOLDER
Add real, sanitized screenshots of the running application under docs/screenshots/
(no real targets, IP addresses, credentials or personal data), then reference them, e.g.:

![Dashboard](docs/screenshots/dashboard.png)
![Scan results](docs/screenshots/scan-results.png)

Do not use mock or generated images.
-->

## Technology stack

| Layer | Technology |
|---|---|
| Frontend | React ^19.2, TypeScript ~6.0, Vite ^8.3, plain CSS (no UI framework); linting with oxlint |
| Backend | Python, FastAPI 0.142.2, Uvicorn 0.54.0, Pydantic 2.13.5, pydantic-settings 2.15.0 |
| Database | PostgreSQL, SQLAlchemy 2.1.3, psycopg 3.3.6, Alembic 1.20.0 |
| Scanners | Naabu (ports), Nmap (services), Nuclei (templates); versions are not pinned by the project |
| Intelligence | NVD CVE API 2.0 (HTTPS) |
| Optional | Greenbone/OpenVAS through Docker Compose and `gvm-cli` |

**UI design system.** Dark enterprise theme defined with CSS custom properties in `frontend/src/index.css` (background `#0a0f1a`, accent `#3b82f6`, dedicated critical/high/medium/low severity colors, system/Inter font stack with monospace for data). A light palette is applied for print/PDF export.

## System architecture

```mermaid
flowchart LR
    User([Operator]) --> UI["Frontend<br/>React + TypeScript + Vite<br/>127.0.0.1:5173"]
    UI -- "REST / JSON<br/>status polling" --> API["Backend API<br/>FastAPI + Uvicorn<br/>127.0.0.1:8000"]
    API <--> DB[("PostgreSQL<br/>SQLAlchemy + Alembic")]
    API --> SVC["Scan service<br/>(FastAPI BackgroundTasks)"]
    SVC --> DB
    SVC --> NAABU["Naabu<br/>port discovery"]
    SVC --> NMAP["Nmap<br/>service detection"]
    SVC --> NVD["NVD CVE API 2.0"]
    SVC --> NUCLEI["Nuclei<br/>template detection"]
    SVC -. optional .-> GB["Greenbone / OpenVAS<br/>Docker Compose + gvm-cli"]
```

**Data model**

```mermaid
erDiagram
    SCANS ||--o{ HOSTS : has
    HOSTS ||--o{ PORTS : has
    PORTS ||--o| SERVICES : "identified as"
    SERVICES ||--o{ FINDINGS : has
```

Findings carry a `source` of `nvd`, `nuclei` or `greenbone`.

## Scan workflow

```mermaid
flowchart TD
    A["POST /api/scans<br/>target, profile, vulnerability_profile"] --> B{"Valid input?"}
    B -- No --> E400["HTTP 400"]
    B -- Yes --> C["Insert scan: status pending"]
    C --> D["Background task: status running"]
    D --> N["1. Naabu port discovery<br/>common 1-1000, full 1-65535"]
    N --> Q{"Open ports found?"}
    Q -- No --> Z0["status completed<br/>error_message: No reachable/open ports discovered."]
    Q -- Yes --> H["Persist hosts and ports"]
    H --> M["2. Nmap service and version detection"]
    M --> V["3. NVD CVE correlation<br/>needs CPE and version"]
    V --> U["4. Nuclei templates<br/>tags vuln,cve - severity low to critical"]
    U --> G{"GREENBONE_ENABLED?"}
    G -- Yes --> GB["5. Greenbone scan<br/>vulnerability_profile selects config"]
    G -- No --> F["Commit findings<br/>status completed"]
    GB --> F
    D -. "Naabu / Nmap / Nuclei error" .-> X["status failed<br/>error_message set"]
```

Behavior worth knowing:

- Nuclei runs against the normalized target URL. Findings are stored only when their host and port match a discovered service.
- NVD lookup failures and Greenbone errors are logged and skipped; the scan still completes without those findings.
- A port inside the target (`host:8080`) does not change the Naabu range; it only affects the URL given to Nuclei.
- `vulnerability_profile` is stored for every scan but only influences Greenbone (`lightweight` = Base config, `full` = Full and Fast).

## Project directory structure

```text
.
├── README.md
├── start.ps1                    # Windows launcher (backend + frontend)
├── .gitignore
├── backend/
│   ├── requirements.txt
│   ├── alembic.ini
│   ├── .env                     # local only, never committed (git-ignored)
│   ├── app/
│   │   ├── main.py              # FastAPI app, CORS, /api/health
│   │   ├── api/scans.py         # /api/scans routes
│   │   ├── core/                # config.py (settings), database.py (engine/session)
│   │   ├── models/              # scan, host, port, service, finding
│   │   ├── services/scan_service.py   # scan pipeline orchestration
│   │   └── db_test.py           # database connectivity check
│   ├── migrations/              # Alembic environment + 10 revisions
│   ├── test_scan_service.py     # manual script, runs a real scan (not a pytest test)
│   └── test_nmap_integration.py # manual script, runs a real scan (not a pytest test)
├── scanner/
│   ├── target.py                # target normalization
│   ├── risk.py                  # risk classification
│   ├── adapters/                # naabu.py, nmap.py, nuclei.py, greenbone/client.py
│   └── intelligence/            # cpe_mapper.py, cve_client.py, cve_applicability.py
├── frontend/
│   ├── package.json / package-lock.json / vite.config.ts / tsconfig*.json
│   ├── public/
│   └── src/                     # main.tsx, App.tsx, api.ts, types.ts, utils.ts,
│                                # index.css, App.css, pages/ (7), components/ (16), assets/
├── tests/
│   └── test_cve_applicability.py
└── docs/
    └── screenshots/             # not created yet; add sanitized screenshots here
```

## Prerequisites

| Requirement | Notes |
|---|---|
| Windows 10/11 with Windows PowerShell | `start.ps1` launches `powershell` windows |
| Git | To clone the repository |
| Python 3.12+ | Pinned dependencies install on 3.12 |
| Node.js `^20.19` or `>=22.12` and npm | Required by Vite 8 |
| PostgreSQL | Version is not pinned by the project; migrations were verified on 16 |
| Naabu, Nmap, Nuclei | On `PATH` or configured by path, see [scanner tools](#naabu-nmap-and-nuclei) |
| Internet access | NVD lookups and Nuclei templates |
| Docker Desktop (optional) | Only for Greenbone |

## Installation and setup
 
Run all commands from the repository root (`Zyncle-port-scanner`) in PowerShell, unless a step says otherwise.
 
### 1. Clone
 
```powershell
git clone https://github.com/FAJLEIMAM/Zyncle-port-scanner.git
cd Zyncle-port-scanner
```
 
### 2. Backend dependencies
 
```powershell
python -m venv backend\.venv
backend\.venv\Scripts\python.exe -m pip install --upgrade pip
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```
 
`start.ps1` expects the interpreter at `backend\.venv\Scripts\python.exe`.
 
### 3. Frontend dependencies
 
```powershell
npm --prefix frontend ci
```
 
`start.ps1` stops with an error if `frontend\node_modules` is missing (its message suggests `npm install`; `npm ci` installs exactly what `package-lock.json` pins).
 
### PostgreSQL configuration
 
Create a database and an owner role (names are examples). Run as a PostgreSQL superuser, e.g. `psql -U postgres -h localhost`:
 
```sql
CREATE ROLE zyncle_app WITH LOGIN PASSWORD '<STRONG_UNIQUE_PASSWORD>';
CREATE DATABASE zyncle_scanner OWNER zyncle_app;
```
 
These statements fail if the role or database already exists. In that case pick different names (and use them everywhere below, including `DATABASE_URL`), or reuse the existing ones deliberately, for example `ALTER ROLE zyncle_app WITH PASSWORD '<STRONG_UNIQUE_PASSWORD>';`. Do not drop an existing database to make the example work.
 
The application never creates tables itself; the schema exists only after you [apply the migrations](#database-migrations).
 
**Least privilege.** Alembic needs DDL rights (the migrations create and alter tables), but the running API does not: the code only selects, inserts and updates rows and never deletes. Use the owner role in `DATABASE_URL` for the first migration run, then switch `backend\.env` to a DML-only role. For later migrations, set the owner's URL for that one PowerShell session only (environment variables override `.env`), using single quotes so `$` characters in the password are not expanded:
 
```powershell
$env:DATABASE_URL = 'postgresql+psycopg://zyncle_app:<DB_PASSWORD>@localhost:5432/zyncle_scanner'
# ...run the Alembic commands from "Database migrations" in this same session...
Remove-Item Env:DATABASE_URL    # the API then uses the DML-only role from backend\.env again
```
 
- **Precedence.** `backend/app/core/config.py` uses the default `pydantic-settings` sources (no custom ordering), so a process environment variable named `DATABASE_URL` wins over the same key in `backend\.env`, which wins over defaults (`DATABASE_URL` has none, so it is required).
- **Scope.** `$env:` changes last only for the current PowerShell session and its child processes. Close the window or run `Remove-Item` when finished. Variables set persistently (`setx`, Windows system settings) are not removed by `Remove-Item Env:`.
- **Do not start the app from that session.** The windows opened by `.\start.ps1` inherit the session's environment, so the API would silently run with the owner role instead of the DML-only one.
- Percent-encode special characters in the password (for example `@` as `%40`), and double any `'` inside the single-quoted PowerShell string.
Create the runtime role **after the migrations have been applied**. Run this as a PostgreSQL superuser connected to the application database (`psql -U postgres -h localhost -d zyncle_scanner`), because the owner role normally lacks `CREATEROLE` and cannot create roles:
 
```sql
CREATE ROLE zyncle_rw WITH LOGIN PASSWORD '<STRONG_UNIQUE_PASSWORD>';
GRANT CONNECT ON DATABASE zyncle_scanner TO zyncle_rw;
GRANT USAGE ON SCHEMA public TO zyncle_rw;
GRANT SELECT, INSERT, UPDATE ON scans, hosts, ports, services, findings TO zyncle_rw;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO zyncle_rw;
-- tables added by future migrations are not covered automatically; either repeat the grants or add:
ALTER DEFAULT PRIVILEGES FOR ROLE zyncle_app IN SCHEMA public GRANT SELECT, INSERT, UPDATE ON TABLES TO zyncle_rw;
ALTER DEFAULT PRIVILEGES FOR ROLE zyncle_app IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO zyncle_rw;
```
 
How this works with the documented owner:
 
- Tables are owned by whichever role runs the migrations. Following this README that is `zyncle_app`, which owns the database. The current migrations only create tables, indexes and columns in `public` and run two `UPDATE` backfills; they use no extensions and need no superuser rights, so the owner role is sufficient. On PostgreSQL 15 and later the database owner may create objects in `public`; older versions allow it by default (PostgreSQL behavior, not tested here).
- The explicit `GRANT ... ON scans, hosts, ports, services, findings` and `ON ALL SEQUENCES` lines cover the objects that **already exist** (the `id` columns are integer primary keys backed by sequences).
- `ALTER DEFAULT PRIVILEGES FOR ROLE zyncle_app` applies **only to objects that `zyncle_app` creates later**, in schema `public`. It does not change existing objects, and it has no effect on objects created by any other role (for example `postgres`). If you run migrations as a different role, put that role after `FOR ROLE`.
- You can inspect the result in `psql` without changing anything: `\dp scans` (table privileges) and `\ddp` (default privileges).
### Environment variable reference
 
Create `backend\.env` (it is git-ignored). The backend loads it by absolute path (`backend/.env`, resolved from `backend/app/core/config.py`), so the working directory does not matter. Real environment variables take precedence over `.env`. Never commit the file and never paste real values into issues or screenshots.
 
```dotenv
# Required
DATABASE_URL=postgresql+psycopg://zyncle_app:<DB_PASSWORD>@localhost:5432/zyncle_scanner
 
# Optional: scanner executable paths (otherwise resolved from PATH)
# NAABU_PATH=C:/path/to/naabu.exe
# NUCLEI_PATH=C:/path/to/nuclei.exe
# NMAP_PATH=C:/path/to/nmap.exe
 
# Optional: Greenbone (disabled by default)
# GREENBONE_ENABLED=true
# GREENBONE_COMPOSE_DIR=C:/path/to/greenbone-compose
# GREENBONE_USERNAME=<GVM_USERNAME>
# GREENBONE_PASSWORD=<GVM_PASSWORD>
```
 
| Variable | Required | Default | Purpose |
|---|---|---|---|
| `DATABASE_URL` | Yes | none | SQLAlchemy URL. Use `postgresql+psycopg://`. URL-encode special characters in the password. |
| `NAABU_PATH`, `NMAP_PATH`, `NUCLEI_PATH` | No | resolved from `PATH` | Executable overrides. A path that does not exist is an error. |
| `GREENBONE_ENABLED` | No | `false` | Enables the Greenbone stage. |
| `GREENBONE_COMPOSE_DIR` | If enabled | empty | Directory containing the Greenbone compose file. |
| `GREENBONE_COMPOSE_FILE` | No | `compose.yaml` | Compose file name. |
| `GREENBONE_COMPOSE_SERVICE` | No | `gvm-tools` | Compose service that provides `gvm-cli`. |
| `GREENBONE_SOCKET` | No | `/run/gvmd/gvmd.sock` | gvmd socket path inside the container. |
| `GREENBONE_USERNAME` / `GREENBONE_PASSWORD` | If enabled | `admin` / empty | GMP credentials. |
| `GREENBONE_CONFIG_ID` | No | built-in Base config | Config used by the `lightweight` profile. |
| `GREENBONE_SCANNER_ID`, `GREENBONE_PORT_LIST_ID` | No | built-in defaults | Override if your instance differs. |
| `GREENBONE_TIMEOUT_SECONDS` / `GREENBONE_POLL_SECONDS` | No | `7200` / `5` | Scan timeout and polling interval. |
| `GREENBONE_LIGHTWEIGHT_CONFIG_ID`, `GREENBONE_FULL_CONFIG_ID` | No | empty | Declared in settings but **not currently read** by the adapter. |
 
**Set these as real environment variables, not in `.env`.** They are read with `os.getenv`, and `.env` values are not exported to the process environment:
 
| Variable | Default | Purpose |
|---|---|---|
| `NVD_API_KEY` | unset | Optional NVD API key (higher rate limits). |
| `NUCLEI_PROCESS_TIMEOUT` | `900` | Nuclei process timeout in seconds. |
 
```powershell
$env:NVD_API_KEY = "<YOUR_NVD_API_KEY>"   # then start the app from this same session
```
 
**Windows paths in `.env`:** use forward slashes, or unquoted/single-quoted values. Double-quoted values interpret backslash escapes (`"C:\tools\naabu.exe"` is corrupted).
 
### Naabu, Nmap and Nuclei
 
Install the tools from their official sources and make sure they run from PowerShell:
 
- Naabu: <https://github.com/projectdiscovery/naabu>
- Nuclei: <https://github.com/projectdiscovery/nuclei>
- Nmap: <https://nmap.org/download.html>
```powershell
naabu -version
nmap --version
nuclei -version
nuclei -update-templates      # the adapter disables update checks, so install templates yourself
```
 
> **The backend resolves all three executables when it starts.** If any is missing, the API fails to start (including `/api/health`), not just scans.
 
How the adapters invoke them (tuning values are hard-coded in `scanner/adapters/`):
 
| Tool | Invocation |
|---|---|
| Naabu | `-host <host> -p 1-1000\|1-65535 -c 100 -rate 3000 -timeout 1000 -retries 1 -json -silent -duc` (no scan-type flag; Naabu's default applies) |
| Nmap | `-sV --version-light -Pn -T4 -p <discovered ports> -oX -`, 120 s timeout per host |
| Nuclei | `-target <url> -jsonl -silent -timeout 5 -retries 0 -c 25 -rl 100 -bs 25 -no-interactsh -disable-update-check -tags vuln,cve -severity low,medium,high,critical` |
 
Naabu and Nuclei defaults are fast and can be noisy. Review them before scanning anything sensitive.
 
### Optional: Greenbone setup
 
Greenbone is disabled by default and this repository does not ship a Greenbone deployment. To use it:
 
1. Run Greenbone Community Edition under Docker Compose following Greenbone's official documentation, with a `gvm-tools` service that can reach the gvmd socket.
2. Start Docker Desktop and confirm `docker compose version` works.
3. Set `GREENBONE_ENABLED=true`, `GREENBONE_COMPOSE_DIR`, and the credentials in `backend\.env`.
The adapter runs `docker compose -f <file> run --rm -T ... gvm-cli socket ...` and passes credentials through a temporary config file mounted read-only, not on the command line. Built-in default IDs are used for the Base config (`lightweight`) and Full and Fast config (`full`).
 
### Database migrations
 
> **Applying migrations changes the database schema.** Review them and back up any data you care about first.
 
Run these from `backend\` (Alembic looks for `alembic.ini` in the working directory, and commands that load `migrations/env.py` import the `app` package from it).
 
| Command | Connects to PostgreSQL | Changes the database | Prerequisites and notes |
|---|---|---|---|
| `alembic heads` | No | No | Reads the migration scripts only. |
| `alembic upgrade head --sql` | No | No | Generates SQL for review. `DATABASE_URL` must still be set because `env.py` loads the settings, but no connection is made. |
| `alembic current` | Yes | No | PostgreSQL running, database exists, `DATABASE_URL` set. Prints no revision on a fresh database. |
| `pg_dump` | Yes | No | Backup; skip on a brand-new empty database. |
| `alembic upgrade head` | Yes | **Yes** | Creates and alters tables and runs two `UPDATE` backfills. Needs the owner role. Back up first. |
| `alembic check` | Yes | No | Run after upgrading. Errors if the database is not at the head revision or if models and database differ. |
| `pg_restore` | Yes | **Yes** (overwrites) | Only into an empty database. |
 
```powershell
cd backend
.\.venv\Scripts\python.exe -m alembic heads              # read-only, no connection (exactly one head expected)
.\.venv\Scripts\python.exe -m alembic upgrade head --sql # SQL generation only, no connection, no changes
.\.venv\Scripts\python.exe -m alembic current            # read-only, connects to the database
pg_dump -U zyncle_app -h localhost -d zyncle_scanner -F c -f "$env:USERPROFILE\zyncle_backup.dump"   # read-only backup
.\.venv\Scripts\python.exe -m alembic upgrade head       # SCHEMA-CHANGING: applies the migrations
.\.venv\Scripts\python.exe -m alembic check              # read-only, run after the upgrade
cd ..
```
 
`pg_dump` and `pg_restore` ship with PostgreSQL and must be on `PATH`. To restore a backup into an empty database (this overwrites objects with the same names, so never point it at a database whose data you want to keep):
 
```powershell
pg_restore -U zyncle_app -h localhost -d zyncle_scanner --no-owner "$env:USERPROFILE\zyncle_backup.dump"
```
 
- The revision chain is linear (10 revisions at the time of writing; trust `alembic heads` over any ID written here). The last two add `profile` and `vulnerability_profile` to `scans` and backfill existing rows (`common`, `lightweight`).
- `downgrade` paths drop columns and tables and **delete data**; avoid them on databases that hold results.
- Alembic reads `DATABASE_URL` through `app.core.config`; the URL in `alembic.ini` is a placeholder.
Optional connectivity check:
 
```powershell
.\.venv\Scripts\python.exe -m app.db_test      # prints "Database connection successful: 1"
```
 
## Running the application
 
```powershell
.\start.ps1
```
 
If PowerShell blocks the script: `powershell -ExecutionPolicy Bypass -File .\start.ps1`.
 
`start.ps1` verifies that the virtual environment and `frontend\node_modules` exist, then opens two PowerShell windows:
 
| Service | Command (equivalent) | URL |
|---|---|---|
| Backend | `python -m uvicorn app.main:app --app-dir <repo-root> --reload --host 127.0.0.1 --port 8000` (from `backend/`) | <http://127.0.0.1:8000> |
| Frontend | `npm run dev -- --host 127.0.0.1` (from `frontend/`) | <http://127.0.0.1:5173> (check the Vite window if the port differs) |
 
Equivalent manual start (two PowerShell windows, from the repository root):
 
```powershell
# window 1: backend
cd backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir (Resolve-Path ..).Path --reload --host 127.0.0.1 --port 8000
 
# window 2: frontend
cd frontend
npm run dev -- --host 127.0.0.1
```
 
`(Resolve-Path ..).Path` is a PowerShell expression that turns `..` (the repository root, when run from `backend\`) into an absolute path, the same kind of value `start.ps1` passes as `$Root`. The command mirrors the launcher's backend line, but neither it nor the launcher has been executed on Windows during this documentation review.
 
Omitting `--app-dir` makes the backend fail with `ModuleNotFoundError: No module named 'scanner'`, because `scanner/` lives in the repository root, not in `backend/`. Importing the backend requires `DATABASE_URL` to be set and Naabu, Nmap and Nuclei to be resolvable, otherwise it exits at startup.
 
It does **not** check `.env`, PostgreSQL, scanner tools or migrations. `app` is imported from the working directory (`backend/`) and the top-level `scanner/` package from `--app-dir` (the repository root). The paths are interpolated into single-quoted PowerShell strings, so a repository path containing an apostrophe will break the launcher.
 
> The launcher behavior above is taken from reading `start.ps1`. See [Testing and validation](#testing-and-validation) for what has actually been executed.
 
| Resource | URL |
|---|---|
| Swagger UI | <http://127.0.0.1:8000/docs> |
| ReDoc | <http://127.0.0.1:8000/redoc> |
| Health check | <http://127.0.0.1:8000/api/health> |
 
A production build (`npm --prefix frontend run build`) writes to `frontend/dist`. CORS allows only the two dev origins (`localhost:5173`, `127.0.0.1:5173`) in `backend/app/main.py`, and the API address is hard-coded in `frontend/src/api.ts`; change both if you serve the frontend elsewhere.
 
## API documentation
 
Routes extracted from `backend/app/main.py` and `backend/app/api/scans.py`; the frontend (`frontend/src/api.ts`) calls only the three `/api/scans` routes. There is no update or delete route. All responses are JSON.
 
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | `{"status": "ok", "service": "zyncle-port-scanner"}` (not called by the bundled frontend) |
| `POST` | `/api/scans` | Create a scan and start it in the background |
| `GET` | `/api/scans` | Latest 50 scans, newest first, with counts |
| `GET` | `/api/scans/{scan_id}` | Full scan detail |
 
### `POST /api/scans`
 
| Field | Type | Default | Allowed values |
|---|---|---|---|
| `target` | string (required) | none | Hostname or IP, optionally with scheme and port. A single host; ranges and CIDR are not supported. |
| `profile` | string | `common` | `common`, `full` |
| `vulnerability_profile` | string | `lightweight` | `lightweight`, `full` |
 
Values are trimmed and case-insensitive. Returns `200` with `id`, `target` (normalized to a URL), `profile`, `vulnerability_profile`, `status` (`pending`), `started_at` and `completed_at`. Both timestamps are `null` in this response: `started_at` is set when the background task begins and `completed_at` when it ends. Errors: `400` with a `detail` message (invalid profile or target), `422` for a malformed body.
 
```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/scans `
  -ContentType 'application/json' `
  -Body '{"target":"<AUTHORIZED_TARGET>","profile":"common","vulnerability_profile":"lightweight"}'
 
Invoke-RestMethod http://127.0.0.1:8000/api/scans            # history
Invoke-RestMethod http://127.0.0.1:8000/api/scans/<SCAN_ID>  # one scan
```
 
> These examples need the backend running and the migrations applied. Replace `<AUTHORIZED_TARGET>` with a host you are allowed to scan, and `<SCAN_ID>` with a number from the history output (remove the angle brackets; PowerShell treats a literal `<` as an operator). The API does not reject the literal placeholder; it accepts it as a hostname and starts a scan.
 
### `GET /api/scans`
 
Each item: `id`, `target`, `profile`, `vulnerability_profile`, `status`, `started_at`, `completed_at`, `error_message`, and the counts `hosts`, `open_ports`, `services`, `findings`.
 
### `GET /api/scans/{scan_id}`
 
Scan fields as above (without the counts), plus `hosts[]`:
 
- host: `id`, `address`, `hostname`, `status`, `ports[]`. The pipeline stores `status` as `up` and does not populate `hostname`, so it is currently always `null`.
- port: `id`, `port_number`, `protocol`, `state`, `service` (or `null`), `findings[]`. Findings are attached to the port's service, so a port without a detected service has an empty list.
- `service`: `id`, `service_name`, `product`, `version`, `cpe`, `confidence`, `banner`.
- finding: `id`, `title`, `description`, `vulnerability_id`, `severity`, `cvss_score`, `cwe_ids` (comma-separated string), `cvss_metrics`, `risk_level`, `risk_reason`, `source`, `matcher_name`, `evidence`, `detected_at`.
Returns `404` (`"Scan not found"`) for an unknown id.
 
**Scan status values:** `pending` → `running` → `completed` or `failed`. A completed scan with no open ports carries `error_message: "No reachable/open ports discovered."`.

## Testing and validation

Results are split into what was re-checked while auditing this documentation (2026-10-11, Linux, Python 3.12.3, Node 22.22, no network access) and results reported earlier that were **not** re-run. The audit environment had no PostgreSQL, no Naabu/Nmap/Nuclei and no installed backend dependencies, and the copied `frontend/node_modules` contained only Windows native bindings.

**Re-checked during the audit**

| Check | Status |
|---|---|
| `tests/test_cve_applicability.py` collects | ✅ |
| The same 7 tests with line 134 corrected in a temporary copy (repository file untouched) | ✅ 7 of 7 passed |
| `tsc -b` (type-check step of `npm run build`) | ✅ finished without errors |
| Alembic revision chain, read from the `down_revision` values | ✅ one linear chain of 10 revisions, head `28b118ae6d18` |
| `npm ci --dry-run` on a copy of `package.json` and `package-lock.json` | ✅ lockfile in sync with `package.json` |
| `scanner` import with and without the repository root on `sys.path` (basis for `--app-dir`) | ✅ fails from `backend/` alone, succeeds with the root added |
| Vite bundling and `npm run lint` (oxlint) | ✅) |

**Reported earlier by the author, not re-run**

| Check | Reported result |
|---|---|
| `npm --prefix frontend run build` | Passed |
| `npm --prefix frontend run lint` | 0 errors, 1 warning (`react/set-state-in-effect` in `App.tsx`) |
| `pip install -r backend/requirements.txt` | Passed |
| Alembic `upgrade head` and `alembic check` | Passed |
| API smoke test with stub scanners (all routes, 400/404/422, CORS, failure and no-open-ports paths) | Passed |
| Full API flow with a DML-only database role | Passed |

**Checked by reading the source only (not executed):** the `start.ps1` flow, the Uvicorn command, the SQL and `psql`/`pg_dump`/`pg_restore` commands, every Alembic command except the static revision-chain read, the Naabu/Nmap/Nuclei version and template-update commands, and the PowerShell API examples.

**Not verified:** real Naabu, Nmap and Nuclei runs, live NVD lookups, Greenbone, `start.ps1` on Windows, Python 3.14 and PostgreSQL versions other than 16. **Do not exist:** frontend unit/e2e tests, API tests and CI.

<!-- AUTHOR TODO: after fixing tests/test_cve_applicability.py line 134, change the first row to "✅ 7 passed" and re-run the earlier-reported checks to refresh this section. -->

Run from the repository root:

```powershell
backend\.venv\Scripts\python.exe -m pip install pytest
backend\.venv\Scripts\python.exe -m pytest tests -v
npm --prefix frontend run build
npm --prefix frontend run lint
```

> Always pass `tests` to pytest. `backend/test_scan_service.py` and `backend/test_nmap_integration.py` are manual scripts, not tests: they run a real scan of `127.0.0.1` at import time and start with a `sys.path.insert(...)` line containing a hard-coded Windows path that you must edit before use. They must not be collected by pytest.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| Backend exits at startup with `naabu/nmap/nuclei was not found` | `A required scanner executable may be missing from PATH. Install the required tool and verify its executable path, or configure NAABU_PATH, NMAP_PATH, or NUCLEI_PATH if supported by the application`. |
| `database_url Field required` | `Check whether DATABASE_URL is defined and whether the backend loads the expected environment file. Verify the configuration in the backend settings before changing database credentials.`. |
| `relation "scans" does not exist` | The database schema may not have been initialized. Confirm that DATABASE_URL points to the intended database, then inspect the Alembic migration status and apply pending migrations if appropriate. |
| Connection or authentication errors | Verify that PostgreSQL is running, the database exists, the configured credentials are correct, and the database accepts connections at the configured host and port. |
| `start.ps1` reports a missing virtual environment or dependencies | Follow the backend and frontend installation steps above. Confirm that the virtual environment exists and the required packages are installed. [steps 2 and 3](#2-backend-dependencies). |
| `start.ps1` is blocked | Review the PowerShell execution-policy message and follow the documented startup instructions. Do not change the system-wide execution policy unnecessarily. |
| Dashboard shows "API unreachable" | Confirm that the backend is running and reachable at the API URL configured by the frontend. Check the browser console and backend logs for connection or CORS errors. |
| Scan stays `pending` or `running` | Check the backend logs and scan status. Possible causes include a long-running scanner, a backend restart, or a scan that has not completed. Verify the configured timeout for the relevant scanner. |
| Scan `failed` | Inspect the scan's error_message and backend logs. Check scanner availability, target authorization, permissions, configuration, and timeout settings. |
| No findings | An empty result does not necessarily mean the target is secure. Check scanner output, Nmap service/version detection, Nuclei template availability, vulnerability-correlation requirements, and whether optional integrations are enabled. |
| NVD_API_KEY or NUCLEI_PROCESS_TIMEOUT has no effect | Verify how the application reads these settings. If they are read directly from the process environment, define them before starting the backend. |
| npm run build or npm run lint fails with a native-binding error | Dependencies may have been copied from another operating system or architecture. Remove frontend/node_modules and run npm --prefix frontend ci from the repository root. |


## Security considerations

**Authorization.** Obtain explicit written permission before scanning any system you do not own. Unauthorized scanning may be illegal.

| Area | Guidance |
|---|---|
| Secrets | Keep `backend\.env` out of Git; never commit credentials, API keys or private connection URLs. `.gitignore` excludes `.env`, `.env.*`, `.venv/`, `node_modules/`, `dist/`, `__pycache__/` and `*.log`. |
| Database | Use the least-privilege role described above; use a unique strong password. |
| Access control | **The API has no authentication or authorization.** Anyone who can reach port 8000 can launch scans against arbitrary targets and read every stored result. Keep it bound to `127.0.0.1` and do not expose it to a network. CORS is not access control. |
| Target scope | Input is only checked for a valid hostname. There is no allow-list or private-range restriction, so enforce scope yourself. |
| Scan results | Banners, versions and findings are stored in plaintext and exported by the UI as `zyncle-scan-<id>.json/.csv` into the browser's download folder. Treat both as sensitive. |
| Error output | A failed scan's `error_message` is stored and returned by the API; for example a Naabu failure includes the full command line and local executable path, and Nmap/Nuclei failures include the tool's stderr. The Nmap command line is also printed to the backend console. |
| Scanner behavior | Naabu and Nuclei rate/concurrency are hard-coded and aggressive. Nuclei runs with Interactsh disabled; detected product/version strings (CPE) are sent to the NVD API. |
| Migrations | Review the SQL and back up data before applying; avoid downgrades on real data. |

## Known limitations

- Single-target scans only; no CIDR, ranges or target lists. Port discovery uses Naabu's default scan type; UDP is not configured.
- No authentication, users, queue, scan cancellation or recovery of interrupted scans. Scans run in-process via `BackgroundTasks`.
- History returns only the latest 50 scans, without pagination.
- The API reports overall status only, so the UI cannot show per-stage progress.
- `vulnerability_profile` affects only Greenbone; findings are stored only when matched to a discovered service.
- Tool tuning is hard-coded; only the executable paths and the Nuclei timeout are configurable. The Naabu process has no timeout.
- Frontend uses state-based navigation (no URL routing); API address and CORS origins are fixed to local development values.
- `start.ps1` is Windows-only and breaks on repository paths containing an apostrophe. No Dockerfile, CI, or Linux/macOS launcher is provided.
- The two manual scripts in `backend/` contain a hard-coded local path and run real scans when imported.
- Test coverage is limited to one unit-test module (CVE version applicability); there are no API or frontend tests.

## Future improvements

Proposals, not implemented features:

- Authentication and a configurable target allow-list.
- Per-stage progress reporting, scan cancellation and recovery of interrupted scans.
- Configurable scan tuning (rate, concurrency, timeouts) and a configurable API base URL for the frontend.
- Pagination for history; server-side report export.
- API and frontend tests, plus CI.
- Cross-platform launch scripts and containerization.

## Contributing

No formal contribution process has been defined. To propose a change, open an issue first. Before submitting, run the [validation commands](#testing-and-validation), keep migrations reviewed, and never commit secrets.

## License

This project is licensed under the MIT License.

Copyright (c) 2026 Fajle Imam.

## Author

Fajle Imam.
