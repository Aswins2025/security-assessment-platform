"""
Client-Side Security checks: security response headers that protect against
clickjacking, MIME sniffing, XSS via missing CSP, etc. Passive checks only.
"""
import httpx

from app.scanners.base import FindingDraft

CATEGORY_KEY = "CLIENT-SIDE"
CATEGORY_LABEL = "Client-Side Security"

REQUIRED_HEADERS = {
    "Content-Security-Policy": {
        "check_id": "CSP-001",
        "title": "Missing Content-Security-Policy (CSP) header",
        "recommendation": "Implement a restrictive CSP to mitigate XSS and data-injection attacks.",
        "impact": 4, "likelihood": 3,
    },
    "X-Frame-Options": {
        "check_id": "CSP-002",
        "title": "Missing X-Frame-Options header",
        "recommendation": "Set 'X-Frame-Options: DENY' or use CSP frame-ancestors to prevent clickjacking.",
        "impact": 3, "likelihood": 3,
    },
    "X-Content-Type-Options": {
        "check_id": "CSP-003",
        "title": "Missing X-Content-Type-Options header",
        "recommendation": "Set 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing attacks.",
        "impact": 2, "likelihood": 3,
    },
    "Referrer-Policy": {
        "check_id": "CSP-004",
        "title": "Missing Referrer-Policy header",
        "recommendation": "Set a restrictive Referrer-Policy (e.g. 'strict-origin-when-cross-origin').",
        "impact": 2, "likelihood": 2,
    },
    "Permissions-Policy": {
        "check_id": "CSP-005",
        "title": "Missing Permissions-Policy header",
        "recommendation": "Define a Permissions-Policy to restrict access to sensitive browser features.",
        "impact": 2, "likelihood": 2,
    },
}


async def run(base_url: str, client: httpx.AsyncClient):
    findings = []
    try:
        resp = await client.get(base_url, follow_redirects=True)
    except Exception as e:
        findings.append(FindingDraft(
            check_id="CSP-000",
            category_key=CATEGORY_KEY,
            category_label=CATEGORY_LABEL,
            title="Could not fetch target for client-side header checks",
            affected_component=base_url,
            evidence=str(e),
            recommendation="Verify target availability and re-run the scan.",
            impact=1, likelihood=1,
        ))
        return [f.to_persisted_dict() for f in findings]

    for header, meta in REQUIRED_HEADERS.items():
        if header not in resp.headers:
            findings.append(FindingDraft(
                check_id=meta["check_id"],
                category_key=CATEGORY_KEY,
                category_label=CATEGORY_LABEL,
                title=meta["title"],
                affected_component=base_url,
                evidence=f"Response headers did not include '{header}'.",
                recommendation=meta["recommendation"],
                impact=meta["impact"], likelihood=meta["likelihood"],
            ))

    # Inline script detection (very lightweight passive heuristic)
    body = resp.text if resp.text else ""
    if "<script>" in body.lower():
        findings.append(FindingDraft(
            check_id="CSP-006",
            category_key=CATEGORY_KEY,
            category_label=CATEGORY_LABEL,
            title="Inline <script> blocks detected without a nonce/hash",
            affected_component=base_url,
            evidence="Response HTML contains inline <script> tags, which weakens CSP effectiveness.",
            recommendation="Move inline scripts to external files or use CSP nonces/hashes.",
            impact=2, likelihood=2,
        ))

    return [f.to_persisted_dict() for f in findings]
