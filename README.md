# Zyncle Port Scanner

**An integrated port scanning and vulnerability assessment platform with a modern security dashboard.**

![Backend](https://img.shields.io/badge/Backend-FastAPI-009688)
![Frontend](https://img.shields.io/badge/Frontend-React%20%2B%20TypeScript-3178C6)
![Database](https://img.shields.io/badge/Database-PostgreSQL-4169E1)
![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB)

> **Authorized use only:** Scan only systems you own or have explicit permission to assess.

## Overview

Zyncle Port Scanner is a web-based security assessment application that combines port discovery, service detection, and vulnerability analysis into a single workflow. It provides a centralized dashboard to review scan results, identify potential risks, and track previous scans.

The application integrates existing security tools and stores scan results in a PostgreSQL database for structured analysis and reporting.

## Key Features

- **Port Discovery:** Discover open ports using Naabu.
- **Service Detection:** Identify services and versions using Nmap.
- **Vulnerability Analysis:** Correlate detected service information with CVE data from the NVD API.
- **Template-Based Detection:** Integrate Nuclei for vulnerability checks.
- **Risk Classification:** Organize vulnerability findings by severity and risk.
- **Scan History:** Store and review previous scan results.
- **Security Dashboard:** Explore hosts, ports, services, and vulnerability findings.
- **Data Export:** Export scan results in JSON and CSV formats, with print-to-PDF support.
- **Optional Integration:** Support for Greenbone/OpenVAS assessments.
- **Database Migrations:** Manage database schema changes using Alembic.

## Technology Stack

| Component | Technology |
|---|---|
| Frontend | React, TypeScript, Vite |
| Backend | Python, FastAPI |
| Database | PostgreSQL |
| ORM | SQLAlchemy |
| Database Migrations | Alembic |
| Port Scanning | Naabu |
| Service Detection | Nmap |
| Vulnerability Detection | Nuclei |
| Vulnerability Intelligence | NVD CVE API |
| Optional Scanner | Greenbone/OpenVAS |

## Application Architecture

```text
User
 |
 v
React + TypeScript Dashboard
 |
 v
FastAPI REST API
 |
 v
Scan Orchestration Service
 |
 +---- Naabu: Port Discovery
 |
 +---- Nmap: Service Detection
 |
 +---- NVD API: CVE Correlation
 |
 +---- Nuclei: Vulnerability Checks
 |
 +---- Greenbone/OpenVAS: Optional Assessment
 |
 v
PostgreSQL Database
 |
 v
Scan History and Findings Dashboard
```

## Prerequisites

Install the following before running the application:

- Windows 10/11 with PowerShell
- Python 3.12 or a compatible version
- Node.js and npm compatible with Vite 8
- PostgreSQL
- Naabu
- Nmap
- Nuclei
- Git

Internet connectivity is required for NVD lookups and downloading Nuclei templates. Greenbone/OpenVAS is optional.

## Installation and Setup

Run the following commands from the project root directory.

### 1. Install backend dependencies

```powershell
python -m venv backend\.venv
backend\.venv\Scripts\python.exe -m pip install --upgrade pip
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

### 2. Install frontend dependencies

```powershell
npm --prefix frontend ci
```

### 3. Configure PostgreSQL

Create a PostgreSQL database and a database user with appropriate permissions.

Then create a local environment file:

`backend\.env`

Add your database connection string:

```dotenv
DATABASE_URL=postgresql+psycopg://USERNAME:PASSWORD@localhost:5432/DATABASE_NAME
```

Replace the placeholders with your own database details. Use URL-encoded special characters in passwords when required.

**Never commit `.env` files, passwords, API keys, or other credentials to GitHub.**

### 4. Apply database migrations

Ensure PostgreSQL is running and the database connection is configured.

```powershell
Set-Location backend
.\.venv\Scripts\python.exe -m alembic upgrade head
Set-Location ..
```

### 5. Verify scanner tools

Ensure Naabu, Nmap, and Nuclei are installed and available in your system's `PATH`.

```powershell
naabu -version
nmap --version
nuclei -version
```

If the executables are not in `PATH`, configure their paths using the supported environment variables:

- `NAABU_PATH`
- `NMAP_PATH`
- `NUCLEI_PATH`

### 6. Start the application

From the project root:

```powershell
.\start.ps1
```

The launcher opens the backend and frontend in separate PowerShell windows.

If script execution is blocked, you can run:

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

## Access the Application

| Service | URL |
|---|---|
| Web Dashboard | http://127.0.0.1:5173 |
| Backend API | http://127.0.0.1:8000 |
| Swagger API Documentation | http://127.0.0.1:8000/docs |
| ReDoc API Documentation | http://127.0.0.1:8000/redoc |
| Health Check | http://127.0.0.1:8000/api/health |

If the frontend starts on a different port, check the Vite terminal for the actual URL.

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Check API health |
| POST | `/api/scans` | Create and start a scan |
| GET | `/api/scans` | Retrieve recent scans |
| GET | `/api/scans/{scan_id}` | Retrieve detailed scan results |

### Scan Configuration

The scan creation endpoint supports these main parameters:

| Parameter | Description |
|---|---|
| `target` | Hostname or IP address of the authorized target |
| `profile` | Port scanning profile: `common` or `full` |
| `vulnerability_profile` | Vulnerability assessment profile: `lightweight` or `full` |

The application records scan status and organizes results by host, port, service, and finding.

## Security Considerations

- Scan only systems you own or have explicit permission to assess.
- Keep credentials and API keys out of source control.
- Keep the backend bound to localhost unless suitable security controls are implemented.
- The current API does not provide authentication or authorization. Do not expose it to untrusted networks.
- Review scan scope and scanner settings before conducting assessments.
- Treat scan results, service banners, and exported reports as potentially sensitive.
- Review database migrations before applying them to a database containing important data.

## Current Limitations

- Scans currently target one host at a time.
- Authentication and user management are not implemented.
- Scan cancellation and recovery of interrupted scans are limited.
- Some scanner settings are fixed in the code.
- Actual detection results depend on the installed scanner tools, their templates, and the target environment.
- Greenbone/OpenVAS is optional and requires a separate deployment.

## Testing

The frontend production build has previously been verified successfully in the development environment. Backend dependency checks and API checks have also been performed during development.

Actual scanner behavior and all deployment environments should be tested independently before production use.

## Future Improvements

- Add authentication and role-based access control.
- Introduce target allow-listing and stronger scan-scope controls.
- Add scan cancellation, recovery, and detailed stage progress.
- Make scanner tuning and API configuration adjustable.
- Expand automated backend and frontend tests.
- Add CI workflows and containerized deployment.

## License

No license has been specified for this project. Add a license file before authorizing reuse, modification, or redistribution.

## Author

**Fajle Imam**

Developed as an internship project submission.