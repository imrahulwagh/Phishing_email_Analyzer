import pytest
from pathlib import Path
from ingestion.eml_parser import parse_eml, extract_domain

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_extract_domain():
    assert extract_domain("user@paypal.com") == "paypal.com"
    assert extract_domain("Support <security@paypa1-verify.com>") == "paypa1-verify.com"
    assert extract_domain("invalid-address") == ""


def test_parse_legitimate_eml():
    legit_file = FIXTURES_DIR / "legitimate.eml"
    parsed = parse_eml(legit_file)

    assert parsed.sender_domain == "acme-corp.com"
    assert "Sprint Planning" in parsed.subject
    assert parsed.authentication_results != ""
    assert len(parsed.links) > 0
    assert parsed.links[0].href == "https://acme-corp.com/roadmap"


def test_parse_phishing_eml():
    phish_file = FIXTURES_DIR / "phishing.eml"
    parsed = parse_eml(phish_file)

    assert parsed.sender_domain == "paypa1-verify.com"
    assert parsed.reply_to_domain == "evil-attacker.net"
    assert parsed.return_path_domain == "different-domain.org"
    assert "SUSPENDED" in parsed.subject.upper()
    assert len(parsed.images) >= 1
    assert len(parsed.links) >= 1
    assert parsed.links[0].href == "http://evil-phish.net/login-harvest"
    assert "paypal.com" in parsed.links[0].text
