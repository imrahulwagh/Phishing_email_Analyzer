import re
from urllib.parse import urlparse
from typing import List, Dict, Any
from bs4 import BeautifulSoup
from ingestion.eml_parser import ParsedLink


def clean_text(text: str) -> str:
    """Strips HTML tags if present and normalizes whitespace."""
    if not text:
        return ""
    if "<html" in text.lower() or "<body" in text.lower() or "<p" in text.lower():
        text = BeautifulSoup(text, "html.parser").get_text(separator=" ")
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def extract_domain_from_url(url_or_text: str) -> str:
    """Extracts base domain from a URL or domain-like string."""
    clean_str = url_or_text.strip().lower()
    if not clean_str.startswith(("http://", "https://")):
        clean_str = "http://" + clean_str
    try:
        parsed = urlparse(clean_str)
        hostname = parsed.hostname or ""
        if hostname.startswith("www."):
            hostname = hostname[4:]
        return hostname
    except Exception:
        return ""


def check_link_mismatches(links: List[ParsedLink]) -> List[Dict[str, Any]]:
    """
    Analyzes hyperlinks for visual text vs actual href domain mismatches.
    Example: Text shows 'https://paypal.com/verify' but href goes to 'http://malicious-domain.com'
    """
    mismatches = []
    domain_regex = r"(?:https?://)?(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"

    for link in links:
        href = link.href.strip()
        text = link.text.strip()

        # Check if visible text looks like a URL or domain
        text_domain_match = re.search(domain_regex, text)
        if text_domain_match:
            displayed_domain = extract_domain_from_url(text_domain_match.group(0))
            actual_domain = extract_domain_from_url(href)

            if displayed_domain and actual_domain and displayed_domain != actual_domain:
                mismatches.append({
                    "href": href,
                    "displayed_text": text,
                    "displayed_domain": displayed_domain,
                    "actual_domain": actual_domain,
                    "severity": "HIGH"
                })

    return mismatches
