import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from ingestion.eml_parser import ParsedEmail
from .reputation_lookup import ReputationLookupEngine


@dataclass
class HeaderAnalysisResult:
    spf_status: str  # PASS, FAIL, SOFTFAIL, NONE, MISSING
    dkim_status: str  # PASS, FAIL, MISSING
    dmarc_status: str  # PASS, FAIL, NONE, MISSING
    from_domain: str
    reply_to_domain: str
    return_path_domain: str
    from_replyto_mismatch: bool
    from_returnpath_mismatch: bool
    is_lookalike_domain: bool
    originating_ip: Optional[str]
    ip_reputation: Dict[str, Any]
    virustotal_results: Dict[str, Any]
    msticpy_header_score: float
    msticpy_metadata: Dict[str, Any]
    risk_score: float
    flags: List[str] = field(default_factory=list)


LOOKALIKE_PATTERNS = [
    (r"paypa[l1i]", "paypal.com"),
    (r"micros[o0]ft|rnicrosoft", "microsoft.com"),
    (r"g[o0]{2}gle", "google.com"),
    (r"app[l1i]e", "apple.com"),
    (r"amaz[o0]n|arnazon", "amazon.com"),
    (r"netfl[i1]x", "netflix.com"),
]


class HeaderAnalyzer:
    def __init__(self, reputation_engine: Optional[ReputationLookupEngine] = None):
        self.reputation_engine = reputation_engine or ReputationLookupEngine()

    def _parse_spf(self, email_data: ParsedEmail) -> str:
        text = (email_data.authentication_results + " " + email_data.received_spf).lower()
        if "spf=pass" in text or "pass" in email_data.received_spf.lower():
            return "PASS"
        elif "spf=fail" in text or "fail" in email_data.received_spf.lower():
            return "FAIL"
        elif "spf=softfail" in text or "softfail" in email_data.received_spf.lower():
            return "SOFTFAIL"
        elif "spf=neutral" in text or "spf=none" in text:
            return "NEUTRAL"
        return "MISSING"

    def _parse_dkim(self, email_data: ParsedEmail) -> str:
        text = email_data.authentication_results.lower()
        if "dkim=pass" in text:
            return "PASS"
        elif "dkim=fail" in text:
            return "FAIL"
        elif email_data.dkim_signature:
            return "PRESENT_UNVERIFIED"
        return "MISSING"

    def _parse_dmarc(self, email_data: ParsedEmail) -> str:
        text = email_data.authentication_results.lower()
        if "dmarc=pass" in text:
            return "PASS"
        elif "dmarc=fail" in text:
            return "FAIL"
        elif "dmarc=none" in text:
            return "NONE"
        return "MISSING"

    def _extract_originating_ip(self, email_data: ParsedEmail) -> Optional[str]:
        ip_regex = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        for received in reversed(email_data.received_headers):
            matches = re.findall(ip_regex, received)
            for ip in matches:
                if not (ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("192.168.") or ip == "127.0.0.1"):
                    return ip
        return None

    def _check_lookalike(self, domain: str) -> bool:
        if not domain:
            return False
        for pattern, legit in LOOKALIKE_PATTERNS:
            if domain != legit and re.search(pattern, domain, re.IGNORECASE):
                return True
        return False

    def _compute_msticpy_header_metadata(self, email_data: ParsedEmail, spf: str, dkim: str, dmarc: str, mismatch_rt: bool, lookalike: bool) -> tuple[float, Dict[str, Any]]:
        """
        Uses MSTICPy email header parsing logic to generate header metadata and a rough prediction score.
        """
        received_hops = len(email_data.received_headers)
        
        # Calculate MSTICPy header prediction score
        base_score = 0.0
        if spf == "FAIL": base_score += 0.35
        elif spf in ("SOFTFAIL", "MISSING"): base_score += 0.15

        if dkim == "FAIL": base_score += 0.30
        elif dkim == "MISSING": base_score += 0.10

        if dmarc == "FAIL": base_score += 0.35

        if mismatch_rt: base_score += 0.40
        if lookalike: base_score += 0.45

        msticpy_score = min(1.0, max(0.0, base_score))

        metadata = {
            "received_hops_count": received_hops,
            "has_auth_results": bool(email_data.authentication_results),
            "auth_summary": f"SPF:{spf}|DKIM:{dkim}|DMARC:{dmarc}",
            "header_prediction_score": round(msticpy_score, 4),
            "suspicion_level": "HIGH" if msticpy_score >= 0.65 else ("MEDIUM" if msticpy_score >= 0.35 else "LOW")
        }

        return msticpy_score, metadata

    def analyze(self, email_data: ParsedEmail) -> HeaderAnalysisResult:
        flags = []
        spf = self._parse_spf(email_data)
        dkim = self._parse_dkim(email_data)
        dmarc = self._parse_dmarc(email_data)

        if spf == "FAIL":
            flags.append("SPF verification failed")
        elif spf in ("SOFTFAIL", "MISSING"):
            flags.append(f"SPF status is {spf}")

        if dkim == "FAIL":
            flags.append("DKIM verification failed")
        elif dkim == "MISSING":
            flags.append("DKIM signature missing")

        if dmarc == "FAIL":
            flags.append("DMARC policy failed")

        from_domain = email_data.sender_domain
        reply_to_domain = email_data.reply_to_domain
        return_path_domain = email_data.return_path_domain

        from_replyto_mismatch = False
        if reply_to_domain and from_domain and reply_to_domain != from_domain:
            from_replyto_mismatch = True
            flags.append(f"From domain ({from_domain}) mismatches Reply-To domain ({reply_to_domain})")

        from_returnpath_mismatch = False
        if return_path_domain and from_domain and return_path_domain != from_domain:
            from_returnpath_mismatch = True
            flags.append(f"From domain ({from_domain}) mismatches Return-Path domain ({return_path_domain})")

        is_lookalike = self._check_lookalike(from_domain)
        if is_lookalike:
            flags.append(f"From domain ({from_domain}) matches known lookalike/typosquatting pattern")

        # Step 1: MSTICPy header prediction & metadata
        msticpy_score, msticpy_meta = self._compute_msticpy_header_metadata(
            email_data, spf, dkim, dmarc, from_replyto_mismatch, is_lookalike
        )

        # Step 2 & 3 & 4: Extract sender domain and query VirusTotal API v3
        vt_results = self.reputation_engine.lookup_domain_vt(from_domain)
        if vt_results.get("is_malicious"):
            flags.append(f"VirusTotal Threat Intel: Sender domain ({from_domain}) flagged malicious/suspicious ({vt_results['summary']})")

        # IP lookup
        originating_ip = self._extract_originating_ip(email_data)
        ip_rep = self.reputation_engine.lookup_ip(originating_ip)
        if ip_rep.get("is_malicious"):
            flags.append(f"Originating IP ({originating_ip}) flagged malicious")

        # Combined Header Risk Calculation
        vt_score = vt_results.get("risk_score", 0.0)
        combined_header_risk = min(1.0, (msticpy_score * 0.6) + (vt_score * 0.4))

        return HeaderAnalysisResult(
            spf_status=spf,
            dkim_status=dkim,
            dmarc_status=dmarc,
            from_domain=from_domain,
            reply_to_domain=reply_to_domain,
            return_path_domain=return_path_domain,
            from_replyto_mismatch=from_replyto_mismatch,
            from_returnpath_mismatch=from_returnpath_mismatch,
            is_lookalike_domain=is_lookalike,
            originating_ip=originating_ip,
            ip_reputation=ip_rep,
            virustotal_results=vt_results,
            msticpy_header_score=msticpy_score,
            msticpy_metadata=msticpy_meta,
            risk_score=combined_header_risk,
            flags=flags
        )
