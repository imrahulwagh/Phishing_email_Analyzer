import pytest
from pathlib import Path
from ingestion.eml_parser import parse_eml
from scoring import RiskScorer

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_risk_scorer_legitimate():
    legit_file = FIXTURES_DIR / "legitimate.eml"
    parsed = parse_eml(legit_file)
    scorer = RiskScorer()

    assessment = scorer.evaluate_email(parsed)

    assert assessment.verdict == "LEGITIMATE"
    assert assessment.overall_risk_score < 0.45


def test_risk_scorer_phishing():
    phish_file = FIXTURES_DIR / "phishing.eml"
    parsed = parse_eml(phish_file)
    scorer = RiskScorer()

    assessment = scorer.evaluate_email(parsed)

    assert assessment.verdict == "HIGH_RISK_PHISHING"
    assert assessment.overall_risk_score >= 0.65
    assert len(assessment.all_contributing_signals) >= 3

    dict_repr = assessment.to_dict()
    assert "overall_risk_score" in dict_repr
    assert "module_scores" in dict_repr
    assert "header_details" in dict_repr
    assert "image_details" in dict_repr
    assert "content_details" in dict_repr
