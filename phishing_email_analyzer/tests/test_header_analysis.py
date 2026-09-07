import pytest
from pathlib import Path
from ingestion.eml_parser import parse_eml
from header_analysis import HeaderAnalyzer

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_header_analyzer_legitimate():
    legit_file = FIXTURES_DIR / "legitimate.eml"
    parsed = parse_eml(legit_file)
    analyzer = HeaderAnalyzer()

    result = analyzer.analyze(parsed)

    assert result.spf_status == "PASS"
    assert result.dkim_status == "PASS"
    assert result.from_replyto_mismatch is False
    assert result.is_lookalike_domain is False
    assert result.risk_score < 0.30


def test_header_analyzer_phishing():
    phish_file = FIXTURES_DIR / "phishing.eml"
    parsed = parse_eml(phish_file)
    analyzer = HeaderAnalyzer()

    result = analyzer.analyze(parsed)

    assert result.spf_status == "FAIL"
    assert result.dkim_status == "FAIL"
    assert result.from_replyto_mismatch is True
    assert result.from_returnpath_mismatch is True
    assert result.is_lookalike_domain is True
    assert result.risk_score > 0.60
    assert len(result.flags) >= 3
