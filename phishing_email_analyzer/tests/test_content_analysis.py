import pytest
from pathlib import Path
from ingestion.eml_parser import parse_eml
from content_analysis import ContentNLPClassifier, clean_text, check_link_mismatches
from ingestion.eml_parser import ParsedLink

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_link_mismatch_checker():
    links = [
        ParsedLink(href="http://evil-phish.net/login", text="https://www.paypal.com/login"),
        ParsedLink(href="https://google.com/search", text="Click here to search Google")
    ]
    mismatches = check_link_mismatches(links)

    assert len(mismatches) == 1
    assert mismatches[0]["displayed_domain"] == "paypal.com"
    assert mismatches[0]["actual_domain"] == "evil-phish.net"


def test_content_nlp_legitimate():
    legit_file = FIXTURES_DIR / "legitimate.eml"
    parsed = parse_eml(legit_file)
    classifier = ContentNLPClassifier()

    result = classifier.analyze(parsed)

    assert result.has_link_mismatches is False
    assert result.urgency_score < 0.30
    assert result.combined_content_risk_score < 0.40


def test_content_nlp_phishing():
    phish_file = FIXTURES_DIR / "phishing.eml"
    parsed = parse_eml(phish_file)
    classifier = ContentNLPClassifier()

    result = classifier.analyze(parsed)

    assert result.has_link_mismatches is True
    assert result.urgency_score > 0.40
    assert result.combined_content_risk_score > 0.60
    assert len(result.urgency_phrases) >= 1
