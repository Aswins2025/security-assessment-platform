"""
Common building blocks shared by every scanner module.

Each scanner exposes a single async function `run(base_url: str, client: httpx.AsyncClient)
-> list[FindingDraft]`. The orchestrator (scanners/runner.py) calls these and
persists the results as Finding rows in the database.

IMPORTANT / ETHICAL USE NOTE:
All checks in this package are designed to be *passive* or *low-impact active*
checks (inspecting headers, cookies, TLS config, response behavior to benign
requests). They do not attempt exploitation, data exfiltration, denial of
service, or any action beyond what is needed to confirm a misconfiguration.
Scans must only be run against targets where `Project.is_authorized` is True.
"""
from dataclasses import dataclass, field
from typing import Optional

from app.core.scoring import evaluate


@dataclass
class FindingDraft:
    check_id: str
    category_key: str          # e.g. "TRANSPORT-SECURITY" -> used for scoring lookup
    category_label: str        # human-readable, e.g. "Secure Communication"
    title: str
    affected_component: str
    evidence: str
    recommendation: str
    impact: Optional[int] = None       # 1-5, overrides default weight if set
    likelihood: Optional[int] = None   # 1-5, overrides default weight if set

    def to_persisted_dict(self) -> dict:
        score, severity = evaluate(self.category_key, self.impact, self.likelihood)
        return {
            "check_id": self.check_id,
            "category": self.category_label,
            "title": self.title,
            "severity": severity.value,
            "risk_score": score,
            "affected_component": self.affected_component,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }
