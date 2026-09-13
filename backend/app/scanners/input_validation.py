"""
Input Validation checks (passive/indicator-based only).

This module deliberately avoids sending real exploit payloads (e.g. SQLi/XSS
strings designed to trigger a vulnerable code path). Instead it sends benign,
clearly-non-malicious probe characters and looks for *indicators* in the
response (reflected input, verbose DB errors) that suggest a deeper, manual,
authorized test is warranted. This keeps the scanner safe to run against
production-like environments while still surfacing real signal.
"""
import httpx

from app.scanners.base import FindingDraft

CATEGORY_KEY = "INPUT-VALIDATION"
CATEGORY_LABEL = "Input Validation"

# Benign probe value — not an attack payload, just an unusual but harmless string
PROBE_VALUE = "secTest_' \"<>1"

DB_ERROR_INDICATORS = [
    "sql syntax", "mysql_fetch", "you have an error in your sql",
    "unclosed quotation mark", "sqlstate", "ora-00933", "pg_query",
]


async def run(base_url: str, client: httpx.AsyncClient):
    findings = []
    probe_url = f"{base_url.rstrip('/')}/?q={httpx.QueryParams({'q': PROBE_VALUE})['q']}"

    try:
        resp = await client.get(probe_url, follow_redirects=True)
        body = resp.text or ""
        body_lower = body.lower()

        # Reflected input without encoding (potential stored/reflected XSS surface)
        if PROBE_VALUE in body:
            findings.append(FindingDraft(
                check_id="INP-001",
                category_key=CATEGORY_KEY,
                category_label=CATEGORY_LABEL,
                title="Unencoded reflection of user-supplied input detected",
                affected_component=probe_url,
                evidence="A benign probe string was reflected in the response body without HTML-encoding.",
                recommendation="Context-appropriately encode/escape all user-supplied input before rendering it, "
                                "and validate this further with authorized manual XSS testing.",
                impact=4, likelihood=3,
            ))

        hit = next((i for i in DB_ERROR_INDICATORS if i in body_lower), None)
        if hit:
            findings.append(FindingDraft(
                check_id="INP-002",
                category_key=CATEGORY_KEY,
                category_label=CATEGORY_LABEL,
                title="Database error message disclosed in response",
                affected_component=probe_url,
                evidence=f"Response contained database error indicator: '{hit}'.",
                recommendation="Use parameterized queries/ORM methods and suppress raw DB errors from client responses; "
                                "follow up with authorized manual SQL injection testing.",
                impact=5, likelihood=3,
            ))
    except Exception:
        pass

    return [f.to_persisted_dict() for f in findings]
