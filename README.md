# Automated Security Assessment and Vulnerability Analysis Platform

A full-stack platform for running structured, authorized security checks
against web applications, scoring and prioritizing findings by risk, and
generating shareable HTML/PDF assessment reports.

Before using this tool against any target, read `docs/scope_and_authorization.md`
and confirm you have written authorization to test that target.** The
platform enforces an `is_authorized` flag at the project level, but that is
a workflow safeguard, not a substitute for real authorization.

---

## Architecture

```
security-assessment-platform/
├── backend/    FastAPI + SQLAlchemy + SQLite (swap for Postgres in prod)
├── frontend/   React + Vite + Tailwind + Recharts
└── docs/       Scope & authorization template
```

Checks are organized into 7 categories matching the abstract:
authentication & session management, authorization & access control, input
validation, API security, client-side security, secure communication
(TLS/HSTS), and data storage protection. Each check produces a `Finding`
with a category, severity (Critical/High/Medium/Low/Informational), a
0–10 risk score, evidence, and a remediation recommendation.

---

## 1. Prerequisites

- Python 3.10+
- Node.js 18+ and npm
- (Optional, for PDF reports) system libraries required by WeasyPrint —
  see https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation
  for your OS. HTML reports work without this.

---

## 2. Backend setup (VS Code terminal)

```bash
cd security-assessment-platform/backend

# create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# install dependencies
pip install -r requirements.txt

# create your local env file
cp .env.example .env
# then open .env and set a real random SECRET_KEY

# run the API (auto-reload for development)
uvicorn app.main:app --reload
```

The API will be live at `http://localhost:8000`.
Interactive API docs (Swagger UI) are auto-generated at
`http://localhost:8000/docs` — useful for testing endpoints directly before
the frontend is wired up.

A SQLite database file (`security_assessment.db`) is created automatically
in `backend/` on first run. To reset all data during development, stop the
server and delete that file.

### Running backend tests

```bash
cd security-assessment-platform/backend
pytest -v
```

---

## 3. Frontend setup (separate VS Code terminal)

```bash
cd security-assessment-platform/frontend
npm install
npm run dev
```

The dashboard will be live at `http://localhost:5173` and is already
configured (in `src/api/client.js`) to talk to the backend at
`http://localhost:8000`. If you change the backend port or host, update
`API_BASE_URL` in that file and the CORS `allow_origins` list in
`backend/app/main.py`.

---

## 4. Using the platform

1. Open `http://localhost:5173`, register an analyst account, and log in.
2. Click **+ New Project**, enter the target base URL, and — critically —
   check the authorization confirmation box and fill in the authorization
   note (who approved it, scope, date). Projects cannot be scanned without
   this.
3. Click **Run Scan**. The scan runs asynchronously; the Scan Detail page
   polls automatically until it completes.
4. Review findings in the table (filterable by severity) and the risk
   distribution chart.
5. Click **View HTML Report** or **Download PDF** to generate the
   shareable assessment report for that scan.

---

## 5. Extending the platform

- **Add a new check**: create a new async `run(base_url, client)` function
  in `backend/app/scanners/`, following the pattern in any existing module
  (return a list of `FindingDraft.to_persisted_dict()` results), then
  register it in `SCANNER_REGISTRY` in `backend/app/scanners/runner.py`.
- **Adjust severity weighting**: edit `DEFAULT_WEIGHTS` in
  `backend/app/core/scoring.py`, or pass explicit `impact`/`likelihood`
  values when constructing a `FindingDraft`.
- **Authenticated / role-based access-control testing**: the
  `access_control.py` scanner currently only checks for publicly exposed
  sensitive paths. To test that a low-privilege test account can't reach
  admin-only endpoints, extend this module to accept a test-account token
  and attempt authenticated requests against known privileged routes —
  always using dedicated test accounts, never real user credentials.
- **Mobile app static analysis**: for the mobile side of the abstract,
  pair this platform with an offline static-analysis pass (e.g. MobSF or
  `mobsfscan` against the APK/IPA) and import notable findings manually as
  additional `Finding` rows, or write a small script that calls the
  `/scans` and finding-creation logic to ingest them programmatically.
- **Switch to PostgreSQL for production**: set `DATABASE_URL` in `.env` to
  a Postgres connection string (e.g.
  `postgresql://user:pass@localhost:5432/security_assessment`) and add
  `psycopg2-binary` (already in `requirements.txt`).

---

## 6. Ethical use statement

This platform is designed for **defensive security assessment** of systems
you own or are explicitly authorized to test. All included checks are
passive or low-impact active checks — none attempt exploitation, data
exfiltration, credential brute-forcing, or denial of service. Do not point
it at third-party systems without written authorization.
