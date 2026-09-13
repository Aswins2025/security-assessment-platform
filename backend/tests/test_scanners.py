"""
Basic unit tests for the scoring engine and one scanner module.
Run with:  pytest -v   (from the backend/ directory)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.scoring import compute_risk_score, score_to_severity, evaluate


def test_compute_risk_score_bounds():
    assert compute_risk_score(1, 1) == 0.4
    assert compute_risk_score(5, 5) == 10.0


def test_score_to_severity_bands():
    assert score_to_severity(9.0).value == "Critical"
    assert score_to_severity(7.0).value == "High"
    assert score_to_severity(4.0).value == "Medium"
    assert score_to_severity(2.0).value == "Low"
    assert score_to_severity(0.5).value == "Informational"


def test_evaluate_uses_default_weights():
    score, severity = evaluate("TRANSPORT-SECURITY")
    assert 0 <= score <= 10
    assert severity is not None


def test_finding_draft_to_dict():
    from app.scanners.base import FindingDraft

    draft = FindingDraft(
        check_id="TEST-001",
        category_key="CLIENT-SIDE",
        category_label="Client-Side Security",
        title="Test finding",
        affected_component="https://example.com",
        evidence="unit test evidence",
        recommendation="unit test recommendation",
    )
    result = draft.to_persisted_dict()
    assert result["check_id"] == "TEST-001"
    assert "severity" in result
    assert "risk_score" in result
