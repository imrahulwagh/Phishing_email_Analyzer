import pytest
from pathlib import Path
from ingestion.eml_parser import parse_eml
from image_analysis import LogoDetector

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_logo_detector_phishing():
    phish_file = FIXTURES_DIR / "phishing.eml"
    parsed = parse_eml(phish_file)
    detector = LogoDetector()

    result = detector.analyze(parsed)

    assert result.total_images_extracted >= 1
    assert result.has_unauthorized_logo_impersonation is True
    assert result.risk_score >= 0.70
    assert len(result.brand_matches) >= 1
    assert result.brand_matches[0].brand_name == "paypal"
    assert result.brand_matches[0].domain_authorized is False
