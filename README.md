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
- Docker & Docker Compose (Optional for containerized deployment)
- (Optional, for deeper scanning) Nmap, Trivy, OWASP ZAP, OpenVAS/Greenbone — the platform works fully without these using its built-in live scanners.

### Local Setup Instructions

1. Navigate to the project root directory.

2. Install python dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```

3. Launch the FastAPI server:
   ```bash
   python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
   ```

4. Access the web interface in your browser:
   `http://localhost:8000`
   You'll land on the login screen — sign in with one of the default accounts above.

5. Interactive OpenAPI Swagger documentation:
   `http://localhost:8000/docs`

### A note on live scanning and network access

Because scans are run **live** against the actual target, the machine running SecureScan AI needs outbound network access to whatever you're scanning. If you're testing in a sandboxed/offline environment, scan an internal/reachable target (e.g. `127.0.0.1`, a host on your own network, or an uploaded code archive for SAST) to see full results — scans against unreachable targets will simply report "unreachable" findings and complete without a false positive.

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
│   ├── config.py              # Application settings & JWT key config
│   ├── models.py              # Pydantic schemas & data models
│   ├── scanners.py            # Live dynamic scan engines (port/HTTP/TLS/SAST) + optional tool wrappers
│   ├── storage.py             # JSON-backed persistence (scans, assets, CVEs, users)
│   ├── requirements.txt       # Python dependencies
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

- Added a full login system (JWT-based) with Admin/User roles; every API route and every UI tab now requires authentication.
- Replaced the purely canned vulnerability catalogs with real, live dynamic scanning: live port scans, live HTTP header analysis, live TLS checks, and real static code/secret/dependency analysis of uploaded archives.
- Fixed a bug where completed scans were never saved to disk — scan history now persists reliably across restarts.
- Rewrote the AI risk summary generator so business-impact/recommendation text is produced dynamically from each scan's actual findings instead of a fixed template.
- Rebuilt the executive report with a plain-language risk gauge and severity glossary aimed at non-technical readers.
- Fixed a broken/duplicated HTML block in the Reports tab.
- Added role-aware UI (destructive actions are hidden from non-admin users) and audit info (who ran each scan, and when) in scan history.
