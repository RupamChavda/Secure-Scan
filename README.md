# SecureScan AI - Enterprise Security & Vulnerability Platform

SecureScan AI is an enterprise-grade Vulnerability Assessment, Security Reporting, and Risk Management Platform similar in architecture to Nessus, OpenVAS, and Qualys.

---

## 🌟 Architecture & Features

1. **Login & Role-Based Access**: Every page and API route requires sign-in. Two roles are seeded out of the box — **Admin** (full control, including deleting scans/assets/CVE records and creating new accounts) and **User** (can launch scans, view dashboards, view/download reports, and use the AI assistant, but cannot delete records).
2. **Executive Dashboard**: Live risk trend metrics, threat score distribution charts, active scan pipeline monitoring.
3. **Multi-Target Launcher**: Supports Website URLs, IP Addresses/Servers, Subnet Ranges, Repositories, Container Images, and Cloud Workloads.
4. **Live Dynamic Vulnerability Scanning** — findings are generated from real, live checks against the actual target, not fixed/canned data:
   - **Web targets**: live HTTP request inspecting real response headers (CSP, HSTS, X-Frame-Options, etc.), cookie security flags, server banner disclosure, and a safe reflected-input probe.
   - **Network/IP targets**: a live TCP connect-scan across 21 common service ports (no external tool required), plus optional deeper scanning via Nmap if it's installed on the host.
   - **Any HTTPS-capable target**: a live TLS handshake checking the negotiated protocol version and certificate expiry.
   - **Uploaded code archives (SAST)**: real static analysis — extracts the archive and scans every file for hardcoded secrets (AWS keys, private keys, API tokens, passwords) via pattern matching, and cross-checks `requirements.txt` / `package.json` dependency versions against a known-vulnerable package table. Optional deeper scanning via Trivy if installed.
   - Optional integrations (used automatically when available on the host): Nmap, Trivy, OWASP ZAP daemon, OpenVAS/Greenbone.
5. **AI Vulnerability Assistant**: Plain-language risk explainer, remediation advice, and patch prioritization, generated dynamically from each scan's actual findings (not a fixed template).
6. **Scan History**: Every scan (queued, running, or completed) is persisted to disk and never lost on restart. The Reports tab shows the full historical list with who ran each scan and when.
7. **Asset Inventory**: Centralized digital footprint asset manager with department tagging and last-scan timestamps.
8. **CVE & NVD Knowledgebase**: Integrated threat catalog displaying CVSS v3.1 scores, CISA Known Exploited Vulnerabilities, and exploit metrics.
9. **Human-Friendly Report Generator**: Exportable HTML/PDF executive reports written for non-technical readers — includes a plain-language risk gauge, a glossary explaining what Critical/High/Medium/Low actually mean for the business, and a step-by-step fix plan — plus a raw JSON export for technical/compliance use.

---

## 🔑 Default Login Credentials

| Role  | Username | Password   | Permissions |
|-------|----------|------------|-------------|
| Admin | `admin`  | `admin123` | Full access — can delete scans/assets/CVE records and create new user accounts |
| User  | `user`   | `user123`  | Can launch scans, view the dashboard, view/download reports, and use the AI assistant |

Change these credentials before deploying to production (see `backend/routers/auth.py` — `DEFAULT_USERS_DB`, or use the Admin account to register new accounts via `POST /api/v1/auth/register`).

---

## 🚀 Quickstart Guide

### Prerequisites
- Python 3.10+
- Pip package manager
- **MongoDB** (Local MongoDB Server or MongoDB Compass)
- Docker & Docker Compose (Optional for containerized deployment)
- (Optional, for deeper scanning) Nmap, Trivy, OWASP ZAP, OpenVAS/Greenbone — the platform works fully without these using its built-in live scanners.

### Local Setup Instructions

1. **Navigate to the project root directory**:
   ```bash
   cd Security-platform-main
   ```

2. **Create and Activate a Virtual Environment** (Recommended):
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. **Install python dependencies**:
   ```powershell
   pip install -r backend/requirements.txt
   ```

4. **MongoDB Configuration (MongoDB Compass / Local Server)**:
   - Ensure MongoDB service is running locally on port `27017` (default URI: `mongodb://localhost:27017`).
   - Open **MongoDB Compass**, connect to `mongodb://localhost:27017`, and you will see **`securescan_db`** containing `users`, `assets`, `cves`, and `scans` collections.
   - *Note*: If MongoDB is not running, the application automatically falls back to local JSON file storage in `backend/data/`.

5. **Launch the FastAPI server**:
   Using virtual environment python:
   ```powershell
   .\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload
   ```
   Or if virtual environment is activated:
   ```bash
   uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
   ```

6. **Access the web interface in your browser**:
   - Web App UI: `http://localhost:8000`
   - Interactive OpenAPI Swagger documentation: `http://localhost:8000/docs`


---

## 🐳 Docker Deployment

```bash
docker-compose up --build -d
```

---

## 📁 Repository Directory Structure

```
securescan-ai/
├── backend/
│   ├── main.py                # FastAPI Entry point & routes
│   ├── config.py              # Application settings & MongoDB config
│   ├── database.py            # MongoDB connection & health check manager
│   ├── models.py              # Pydantic schemas & data models
│   ├── scanners.py            # Live dynamic scan engines (port/HTTP/TLS/SAST) + optional tool wrappers
│   ├── storage.py             # MongoDB persistence layer (with JSON fallback)
│   ├── requirements.txt       # Python dependencies (pymongo, motor, fastapi, etc.)
│   └── routers/
│       ├── auth.py            # JWT Authentication, RBAC (Admin/User), login/register
│       ├── assets.py          # Asset Management API
│       ├── scans.py           # Scan Engine, Orchestration & Scan History
│       ├── ai_analysis.py     # AI Risk Synthesizer & Chat Copilot API
│       ├── vulnerabilities.py # CVE & NVD Search API
│       └── reports.py         # Human-friendly PDF/HTML/JSON Report Exporter
├── frontend/
│   ├── index.html             # Single-Page App HTML Interface (incl. login screen)
│   ├── styles.css             # Glassmorphic Dark Cybersecurity Theme
│   └── app.js                 # Frontend SPA Logic, Auth flow, Chart.js Integration
├── Dockerfile                 # Container Build definition
├── docker-compose.yml         # Container Orchestration file
└── README.md                  # System Documentation
```

---

## What changed in this update

- **MongoDB Database Integration**: Connected PyMongo / Motor MongoDB backend storage layer targeting database `securescan_db` (viewable live in MongoDB Compass).
- Added automatic data seeding for `users`, `assets`, and `cves` on startup with fallback to local JSON storage if MongoDB is offline.
- Added virtual environment execution details (`.\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload`) to the startup guide.
- Added a full login system (JWT-based) with Admin/User roles; every API route and every UI tab requires authentication.
- Replaced canned catalogs with live dynamic scanning (ports, HTTP headers, TLS handshake, SAST secret & dependency audits).

