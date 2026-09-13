"""
Authentication & Session Management checks: cookie security attributes,
JWT alg:none acceptance indicator. Passive checks against responses only —
does not attempt credential brute-forcing or login bypass.
"""
import base64
import json

import httpx

from app.scanners.base import FindingDraft

CATEGORY_KEY = "AUTH-SESSION"
CATEGORY_LABEL = "Authentication & Session Management"


def _decode_jwt_header(token: str):
    try:
        header_b64 = token.split(".")[0]
        padded = header_b64 + "=" * (-len(header_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None


async def run(base_url: str, client: httpx.AsyncClient):
    findings = []
    try:
        resp = await client.get(base_url, follow_redirects=True)
    except Exception as e:
        findings.append(FindingDraft(
            check_id="AUTH-000",
            category_key=CATEGORY_KEY,
            category_label=CATEGORY_LABEL,
            title="Could not fetch target for session checks",
            affected_component=base_url,
            evidence=str(e),
            recommendation="Verify target availability and re-run the scan.",
            impact=1, likelihood=1,
        ))
        return [f.to_persisted_dict() for f in findings]

    # Cookie attribute checks
    set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    if not set_cookie_headers:
        # httpx exposes raw headers differently; fall back to cookies jar
        set_cookie_headers = [f"{k}={v}" for k, v in resp.cookies.items()]

    for cookie_str in set_cookie_headers:
        lower = cookie_str.lower()
        cookie_name = cookie_str.split("=")[0]

        if "secure" not in lower:
            findings.append(FindingDraft(
                check_id="AUTH-001",
                category_key=CATEGORY_KEY,
                category_label=CATEGORY_LABEL,
                title=f"Cookie '{cookie_name}' missing Secure flag",
                affected_component=base_url,
                evidence=f"Set-Cookie header for '{cookie_name}' does not include the Secure attribute.",
                recommendation="Set the Secure flag on all cookies so they are only sent over HTTPS.",
                impact=4, likelihood=3,
            ))
        if "httponly" not in lower:
            findings.append(FindingDraft(
                check_id="AUTH-002",
                category_key=CATEGORY_KEY,
                category_label=CATEGORY_LABEL,
                title=f"Cookie '{cookie_name}' missing HttpOnly flag",
                affected_component=base_url,
                evidence=f"Set-Cookie header for '{cookie_name}' does not include the HttpOnly attribute.",
                recommendation="Set the HttpOnly flag to prevent client-side script access to session cookies.",
                impact=4, likelihood=3,
            ))
        if "samesite" not in lower:
            findings.append(FindingDraft(
                check_id="AUTH-003",
                category_key=CATEGORY_KEY,
                category_label=CATEGORY_LABEL,
                title=f"Cookie '{cookie_name}' missing SameSite attribute",
                affected_component=base_url,
                evidence=f"Set-Cookie header for '{cookie_name}' does not include a SameSite attribute.",
                recommendation="Set 'SameSite=Strict' or 'SameSite=Lax' to reduce CSRF exposure.",
                impact=3, likelihood=3,
            ))

    # JWT alg:none indicator — only if a bearer-style token is visible in cookies
    for name, value in resp.cookies.items():
        if value.count(".") == 2:  # looks like a JWT
            header = _decode_jwt_header(value)
            if header and str(header.get("alg", "")).lower() == "none":
                findings.append(FindingDraft(
                    check_id="AUTH-004",
                    category_key=CATEGORY_KEY,
                    category_label=CATEGORY_LABEL,
                    title="JWT issued with 'alg: none'",
                    affected_component=base_url,
                    evidence=f"Token in cookie '{name}' declares algorithm 'none' in its header.",
                    recommendation="Reject tokens with 'alg: none'; enforce a specific signing algorithm server-side.",
                    impact=5, likelihood=2,
                ))

    return [f.to_persisted_dict() for f in findings]
