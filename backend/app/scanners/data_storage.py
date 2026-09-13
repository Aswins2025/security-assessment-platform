"""
Data Storage Protection checks: exposed backup/config files that may contain
credentials or sensitive data. For mobile apps, static analysis of the
APK/IPA (e.g. via MobSF/mobsfscan) is recommended as a complementary,
separate offline step — this module covers the web-reachable surface only.
"""
import httpx

from app.scanners.base import FindingDraft

CATEGORY_KEY = "DATA-STORAGE"
CATEGORY_LABEL = "Data Storage Protection"

EXPOSED_FILE_PATTERNS = [
    "/db.sqlite3", "/database.sql", "/dump.sql", "/config.json.bak",
    "/.DS_Store", "/credentials.json", "/id_rsa", "/.htpasswd",
]


async def run(base_url: str, client: httpx.AsyncClient):
    findings = []
    base = base_url.rstrip("/")

    for path in EXPOSED_FILE_PATTERNS:
        url = base + path
        try:
            resp = await client.get(url, follow_redirects=False)
            if resp.status_code == 200 and len(resp.content) > 0:
                findings.append(FindingDraft(
                    check_id="DATA-001",
                    category_key=CATEGORY_KEY,
                    category_label=CATEGORY_LABEL,
                    title=f"Potentially sensitive data file publicly accessible: {path}",
                    affected_component=url,
                    evidence=f"File returned HTTP 200 with {len(resp.content)} bytes of content.",
                    recommendation=f"Remove '{path}' from the publicly served directory or restrict access to it.",
                    impact=5, likelihood=2,
                ))
        except Exception:
            continue

    return [f.to_persisted_dict() for f in findings]
