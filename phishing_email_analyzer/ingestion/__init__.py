"""
Ingestion module for Phishing Email Analyzer.
"""
from .eml_parser import parse_eml, ParsedEmail

__all__ = ["parse_eml", "ParsedEmail"]
