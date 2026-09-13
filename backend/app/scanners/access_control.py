"""
Authorization & Access Control checks: forced-browsing to commonly sensitive
paths that should not be publicly exposed. This performs only benign GET
requests to well-known paths — it never attempts to guess credentials, access
other users' accounts/data, or bypass authentication.

For deeper role-based access-control testing (e.g. confirming a low-privilege
account cannot reach admin endpoints), the platform expects the analyst to
supply their OWN authorized test accounts via the dashboard; that logic
would extend this module using the same FindingDraft pattern.
"""
import httpx

from app.scanners.base import FindingDraft

CATEGORY_KEY = "ACCESS-CONTROL"
CATEGORY_LABEL = "Authorization & Access Control"

SENSITIVE_PATHS = [
    ("/.env", "Environment configuration file"),
    ("/.git/config", "Exposed Git repository metadata"),
    ("/admin", "Admin panel"),
    ("/backup.zip", "Backup archive"),
    ("/wp-config.php.bak", "Backed-up configuration file"),
    ("/server-status", "Apache server-status page"),
    ("/.aws/credentials", "Cloud credentials file"),
    ("/swagger.json", "Exposed API schema (verify if intentional)"),
]


async def run(base_url: str, client: httpx.AsyncClient):
    findings = []
    base = base_url.rstrip("/")

    for path, description in SENSITIVE_PATHS:
        url = base + path
        try:
            resp = await client.get(url, follow_redirects=False)
            if resp.status_code == 200:
                findings.append(FindingDraft(
                    check_id="ACC-001",
                    category_key=CATEGORY_KEY,
                    category_label=CATEGORY_LABEL,
                    title=f"Potentially sensitive path publicly accessible: {path}",
                    affected_component=url,
                    evidence=f"{description} returned HTTP 200 without authentication.",
                    recommendation=f"Restrict access to '{path}' or remove it from the publicly served directory.",
                    impact=5, likelihood=3,
                ))
        except Exception:
            continue  # unreachable path is not itself a finding

    return [f.to_persisted_dict() for f in findings]
