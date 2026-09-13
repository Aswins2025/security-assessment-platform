"""
Secure Communication checks: TLS version, certificate expiry, HSTS header.
Passive checks only — no traffic interception, no MITM.
"""
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

import httpx

from app.scanners.base import FindingDraft

CATEGORY_KEY = "TRANSPORT-SECURITY"
CATEGORY_LABEL = "Secure Communication"


def _get_cert_info(hostname: str, port: int = 443, timeout: int = 8):
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            protocol = ssock.version()
            return cert, protocol


async def run(base_url: str, client: httpx.AsyncClient):
    findings = []
    parsed = urlparse(base_url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        findings.append(FindingDraft(
            check_id="TLS-001",
            category_key=CATEGORY_KEY,
            category_label=CATEGORY_LABEL,
            title="Application is not served exclusively over HTTPS",
            affected_component=base_url,
            evidence=f"Target base URL uses scheme '{parsed.scheme}'.",
            recommendation="Serve all application traffic over HTTPS and redirect HTTP to HTTPS.",
            impact=5, likelihood=4,
        ))
        return [f.to_persisted_dict() for f in findings]

    # TLS version / certificate check
    try:
        cert, protocol = _get_cert_info(hostname, port)
        if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(FindingDraft(
                check_id="TLS-002",
                category_key=CATEGORY_KEY,
                category_label=CATEGORY_LABEL,
                title="Outdated TLS protocol version in use",
                affected_component=f"{hostname}:{port}",
                evidence=f"Negotiated protocol: {protocol}",
                recommendation="Disable TLS 1.0/1.1/SSLv3 and support only TLS 1.2+.",
                impact=4, likelihood=4,
            ))

        not_after = cert.get("notAfter")
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.utcnow()).days
            if days_left < 0:
                findings.append(FindingDraft(
                    check_id="TLS-003",
                    category_key=CATEGORY_KEY,
                    category_label=CATEGORY_LABEL,
                    title="TLS certificate has expired",
                    affected_component=f"{hostname}:{port}",
                    evidence=f"Certificate expired on {not_after}.",
                    recommendation="Renew the TLS certificate immediately.",
                    impact=5, likelihood=5,
                ))
            elif days_left < 30:
                findings.append(FindingDraft(
                    check_id="TLS-004",
                    category_key=CATEGORY_KEY,
                    category_label=CATEGORY_LABEL,
                    title="TLS certificate is nearing expiry",
                    affected_component=f"{hostname}:{port}",
                    evidence=f"Certificate expires on {not_after} ({days_left} days remaining).",
                    recommendation="Renew the TLS certificate before it expires; consider automated renewal.",
                    impact=3, likelihood=4,
                ))
    except Exception as e:
        findings.append(FindingDraft(
            check_id="TLS-000",
            category_key=CATEGORY_KEY,
            category_label=CATEGORY_LABEL,
            title="Unable to establish/verify TLS connection",
            affected_component=f"{hostname}:{port}",
            evidence=f"Error during TLS handshake inspection: {e}",
            recommendation="Manually verify TLS configuration; this may itself indicate misconfiguration.",
            impact=3, likelihood=2,
        ))

    # HSTS header check
    try:
        resp = await client.get(base_url, follow_redirects=True)
        hsts = resp.headers.get("Strict-Transport-Security")
        if not hsts:
            findings.append(FindingDraft(
                check_id="TLS-005",
                category_key=CATEGORY_KEY,
                category_label=CATEGORY_LABEL,
                title="Missing HTTP Strict-Transport-Security (HSTS) header",
                affected_component=base_url,
                evidence="No Strict-Transport-Security header present in response.",
                recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
                impact=3, likelihood=3,
            ))
    except Exception as e:
        findings.append(FindingDraft(
            check_id="TLS-006",
            category_key=CATEGORY_KEY,
            category_label=CATEGORY_LABEL,
            title="Could not fetch target to verify HSTS header",
            affected_component=base_url,
            evidence=str(e),
            recommendation="Verify target availability and re-run the scan.",
            impact=1, likelihood=1,
        ))

    return [f.to_persisted_dict() for f in findings]
