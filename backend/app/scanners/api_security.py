"""
API Security checks: CORS misconfiguration, verbose error responses,
absence of basic rate-limiting indicators. Passive / low-impact active checks.
"""
import httpx

from app.scanners.base import FindingDraft

CATEGORY_KEY = "API-SECURITY"
CATEGORY_LABEL = "API Security"


async def run(base_url: str, client: httpx.AsyncClient):
    findings = []

    # 1. CORS misconfiguration check
    try:
        resp = await client.get(
            base_url,
            headers={"Origin": "https://attacker-controlled.example"},
            follow_redirects=True,
        )
        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials")
        if acao == "*" and acac and acac.lower() == "true":
            findings.append(FindingDraft(
                check_id="API-001",
                category_key=CATEGORY_KEY,
                category_label=CATEGORY_LABEL,
                title="Insecure CORS configuration (wildcard origin with credentials)",
                affected_component=base_url,
                evidence="Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true.",
                recommendation="Never combine a wildcard origin with credentialed CORS requests; use an explicit allow-list.",
                impact=5, likelihood=3,
            ))
        elif acao and "attacker-controlled.example" in acao:
            findings.append(FindingDraft(
                check_id="API-002",
                category_key=CATEGORY_KEY,
                category_label=CATEGORY_LABEL,
                title="CORS policy reflects arbitrary Origin header",
                affected_component=base_url,
                evidence=f"Server echoed back an untrusted Origin value: {acao}",
                recommendation="Validate Origin against a strict allow-list instead of reflecting the request header.",
                impact=5, likelihood=3,
            ))
    except Exception:
        pass  # target may not support CORS at all — not itself a finding

    # 2. Verbose error / stack trace disclosure check
    try:
        probe_url = base_url.rstrip("/") + "/this-path-should-not-exist-%00"
        resp = await client.get(probe_url, follow_redirects=True)
        body_lower = (resp.text or "").lower()
        indicators = ["traceback (most recent call last)", "stack trace",
                      "at java.", "unhandled exception", "sqlstate", "mysql error"]
        hit = next((i for i in indicators if i in body_lower), None)
        if hit:
            findings.append(FindingDraft(
                check_id="API-003",
                category_key=CATEGORY_KEY,
                category_label=CATEGORY_LABEL,
                title="Verbose error response may disclose internal implementation details",
                affected_component=probe_url,
                evidence=f"Response body contained indicator string: '{hit}'.",
                recommendation="Return generic error messages to clients; log detailed errors server-side only.",
                impact=3, likelihood=3,
            ))
    except Exception:
        pass

    # 3. Basic rate-limiting indicator check (headers only, no flooding)
    try:
        resp = await client.get(base_url, follow_redirects=True)
        rl_headers = [h for h in resp.headers if "ratelimit" in h.lower()]
        if not rl_headers:
            findings.append(FindingDraft(
                check_id="API-004",
                category_key=CATEGORY_KEY,
                category_label=CATEGORY_LABEL,
                title="No rate-limiting indicators observed on API responses",
                affected_component=base_url,
                evidence="No 'X-RateLimit-*' or similar headers were present in the response.",
                recommendation="Implement and expose rate limiting to mitigate brute-force and abuse. "
                                "(Note: absence of headers does not conclusively prove no rate limiting exists; "
                                "confirm manually before treating as a finding in the final report.)",
                impact=2, likelihood=2,
            ))
    except Exception:
        pass

    return [f.to_persisted_dict() for f in findings]
