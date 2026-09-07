import os
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from ingestion.eml_parser import parse_eml, ParsedEmail
from header_analysis import HeaderAnalyzer, HeaderAnalysisResult
from image_analysis import LogoDetector, ImageAnalysisResult
from content_analysis import ContentNLPClassifier, NLPAnalysisResult


@dataclass
class EmailRiskAssessment:
    overall_risk_score: float
    verdict: str  # HIGH_RISK_PHISHING, SUSPICIOUS, LEGITIMATE
    confidence_score: float  # 0.0 to 1.0
    explanation: str  # Short human-readable explanation summary
    risk_threshold: float
    weights_used: Dict[str, float]
    header_result: HeaderAnalysisResult
    image_result: ImageAnalysisResult
    content_result: NLPAnalysisResult
    all_contributing_signals: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_risk_score": round(self.overall_risk_score, 4),
            "verdict": self.verdict,
            "confidence_score": round(self.confidence_score, 4),
            "explanation": self.explanation,
            "risk_threshold": self.risk_threshold,
            "weights": self.weights_used,
            "module_scores": {
                "header": round(self.header_result.risk_score, 4),
                "image": round(self.image_result.risk_score, 4),
                "content": round(self.content_result.combined_content_risk_score, 4),
            },
            "msticpy_analysis": {
                "header_score": self.header_result.msticpy_header_score,
                "metadata": self.header_result.msticpy_metadata
            },
            "virustotal_results": self.header_result.virustotal_results,
            "header_details": {
                "spf_status": self.header_result.spf_status,
                "dkim_status": self.header_result.dkim_status,
                "dmarc_status": self.header_result.dmarc_status,
                "from_domain": self.header_result.from_domain,
                "reply_to_domain": self.header_result.reply_to_domain,
                "domain_mismatch": self.header_result.from_replyto_mismatch,
                "lookalike_domain": self.header_result.is_lookalike_domain,
                "originating_ip": self.header_result.originating_ip
            },
            "image_details": {
                "extracted_count": self.image_result.total_images_extracted,
                "logo_impersonation": self.image_result.has_unauthorized_logo_impersonation,
                "brand_matches": [
                    {
                        "brand": m.brand_name,
                        "hamming_distance": int(m.hamming_distance),
                        "domain_authorized": m.domain_authorized
                    } for m in self.image_result.brand_matches
                ]
            },
            "content_details": {
                "ml_probability": round(self.content_result.ml_phishing_probability, 4),
                "urgency_score": round(self.content_result.urgency_score, 4),
                "urgency_phrases": self.content_result.urgency_phrases,
                "link_mismatches": self.content_result.link_mismatches
            },
            "contributing_signals": self.all_contributing_signals
        }


class RiskScorer:
    def __init__(
        self,
        weight_header: float = 0.35,
        weight_image: float = 0.25,
        weight_content: float = 0.40,
        risk_threshold: float = 0.65,
        header_analyzer: Optional[HeaderAnalyzer] = None,
        logo_detector: Optional[LogoDetector] = None,
        content_classifier: Optional[ContentNLPClassifier] = None
    ):
        env_threshold = os.getenv("DEFAULT_RISK_THRESHOLD")
        if env_threshold:
            try:
                risk_threshold = float(env_threshold)
            except ValueError:
                pass

        total = weight_header + weight_image + weight_content
        self.w_header = weight_header / total
        self.w_image = weight_image / total
        self.w_content = weight_content / total
        self.risk_threshold = risk_threshold

        self.header_analyzer = header_analyzer or HeaderAnalyzer()
        self.logo_detector = logo_detector or LogoDetector()
        self.content_classifier = content_classifier or ContentNLPClassifier()

    def _calculate_confidence(self, s_header: float, s_image: float, s_content: float, vt_available: bool, num_signals: int) -> float:
        """Calculates confidence score [0.0, 1.0] based on signal agreement and threat intel availability."""
        scores = [s_header, s_image, s_content]
        avg = sum(scores) / len(scores)
        variance = sum((x - avg) ** 2 for x in scores) / len(scores)
        agreement_factor = max(0.5, 1.0 - (variance ** 0.5))

        vt_boost = 0.15 if vt_available else 0.05
        signal_boost = min(0.20, num_signals * 0.04)

        raw_confidence = (agreement_factor * 0.65) + vt_boost + signal_boost
        return min(0.99, max(0.50, raw_confidence))

    def _generate_explanation(self, verdict: str, header: HeaderAnalysisResult, image: ImageAnalysisResult, content: NLPAnalysisResult) -> str:
        """Generates a short, human-readable summary explanation."""
        reasons = []

        if header.virustotal_results.get("is_malicious"):
            reasons.append(f"VirusTotal flagged sender domain '{header.from_domain}' as malicious.")

        if header.msticpy_header_score >= 0.60:
            reasons.append(f"MSTICPy header analysis detected SPF/DKIM authentication failures or lookalike domain '{header.from_domain}'.")
        elif header.from_replyto_mismatch:
            reasons.append(f"Header domain mismatch between From '{header.from_domain}' and Reply-To '{header.reply_to_domain}'.")

        if image.has_unauthorized_logo_impersonation and image.brand_matches:
            brand = image.brand_matches[0].brand_name.upper()
            reasons.append(f"Perceptual image analysis detected unauthorized '{brand}' logo impersonation.")

        if content.has_link_mismatches:
            m = content.link_mismatches[0]
            reasons.append(f"Mismatched link text showing '{m['displayed_domain']}' pointing to actual URL domain '{m['actual_domain']}'.")

        if content.urgency_score >= 0.50:
            reasons.append(f"Coercive urgency language detected ('{', '.join(content.urgency_phrases[:3])}').")

        if content.ml_phishing_probability >= 0.70:
            reasons.append(f"NLP ML model predicted high phishing language probability ({content.ml_phishing_probability:.1%}).")

        if verdict == "HIGH_RISK_PHISHING":
            if reasons:
                return "Flagged as HIGH RISK PHISHING due to: " + " ".join(reasons)
            return "Flagged as HIGH RISK PHISHING due to cumulative security anomalies across email headers, images, and content."
        elif verdict == "SUSPICIOUS":
            if reasons:
                return "Flagged as SUSPICIOUS due to: " + " ".join(reasons)
            return "Flagged as SUSPICIOUS: Contains minor header anomalies or urgency indicators requiring caution."
        else:
            return "Verified as LEGITIMATE: Email headers authenticated (SPF/DKIM pass), no logo impersonation, and content is clean."

    def evaluate_email(self, email_data: ParsedEmail) -> EmailRiskAssessment:
        header_res = self.header_analyzer.analyze(email_data)
        image_res = self.logo_detector.analyze(email_data)
        content_res = self.content_classifier.analyze(email_data)

        weighted_score = (
            (header_res.risk_score * self.w_header) +
            (image_res.risk_score * self.w_image) +
            (content_res.combined_content_risk_score * self.w_content)
        )
        weighted_score = min(1.0, max(0.0, weighted_score))

        all_signals = []
        all_signals.extend(header_res.flags)
        all_signals.extend(image_res.flags)
        all_signals.extend(content_res.flags)

        if weighted_score >= self.risk_threshold:
            verdict = "HIGH_RISK_PHISHING"
        elif weighted_score >= max(0.35, self.risk_threshold - 0.25):
            verdict = "SUSPICIOUS"
        else:
            verdict = "LEGITIMATE"

        confidence = self._calculate_confidence(
            header_res.risk_score,
            image_res.risk_score,
            content_res.combined_content_risk_score,
            header_res.virustotal_results.get("vt_available", False),
            len(all_signals)
        )

        explanation = self._generate_explanation(verdict, header_res, image_res, content_res)

        weights_used = {
            "header": round(self.w_header, 2),
            "image": round(self.w_image, 2),
            "content": round(self.w_content, 2)
        }

        return EmailRiskAssessment(
            overall_risk_score=weighted_score,
            verdict=verdict,
            confidence_score=confidence,
            explanation=explanation,
            risk_threshold=self.risk_threshold,
            weights_used=weights_used,
            header_result=header_res,
            image_result=image_res,
            content_result=content_res,
            all_contributing_signals=all_signals
        )
