"""
Simplified risk-scoring engine.

Each finding is assigned an `impact` and `likelihood` weight (1-5 scale).
risk_score = (impact * likelihood) / 2.5   -> normalized to a 0-10 scale
severity is then derived from the risk_score band.

This intentionally mirrors the spirit of CVSS without requiring a full
CVSS vector calculator, which keeps it transparent and easy to tune
for a course/capstone-style project while still being defensible in a
report (documented, reproducible formula).
"""
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


# Default impact/likelihood weights per check category.
# You can override per-finding when a scanner has more specific context.
DEFAULT_WEIGHTS = {
    "AUTH-SESSION": {"impact": 4, "likelihood": 4},
    "ACCESS-CONTROL": {"impact": 5, "likelihood": 3},
    "INPUT-VALIDATION": {"impact": 5, "likelihood": 3},
    "API-SECURITY": {"impact": 4, "likelihood": 3},
    "CLIENT-SIDE": {"impact": 3, "likelihood": 3},
    "TRANSPORT-SECURITY": {"impact": 4, "likelihood": 4},
    "DATA-STORAGE": {"impact": 5, "likelihood": 2},
}


def compute_risk_score(impact: int, likelihood: int) -> float:
    """Returns a 0-10 risk score from 1-5 impact/likelihood weights."""
    impact = max(1, min(5, impact))
    likelihood = max(1, min(5, likelihood))
    raw = (impact * likelihood) / 2.5  # max 5*5/2.5 = 10
    return round(raw, 1)


def score_to_severity(score: float) -> Severity:
    if score >= 8.0:
        return Severity.CRITICAL
    if score >= 6.0:
        return Severity.HIGH
    if score >= 3.5:
        return Severity.MEDIUM
    if score >= 1.0:
        return Severity.LOW
    return Severity.INFO


def evaluate(category_key: str, impact: int = None, likelihood: int = None):
    """
    Convenience helper: given a category key (e.g. 'TRANSPORT-SECURITY'),
    returns (risk_score, severity) using default weights unless overridden.
    """
    weights = DEFAULT_WEIGHTS.get(category_key, {"impact": 3, "likelihood": 3})
    i = impact if impact is not None else weights["impact"]
    l = likelihood if likelihood is not None else weights["likelihood"]
    score = compute_risk_score(i, l)
    return score, score_to_severity(score)
