import re
from dataclasses import dataclass, field
from typing import List, Dict, Any


URGENCY_PATTERNS = [
    (r"\b(?:immediately|urgent|immediate action required|act now|within 24 hours|24-48 hours|final notice)\b", "high_urgency_timeframe"),
    (r"\b(?:account (?:suspended|locked|terminated|restricted|compromised|flagged))\b", "account_status_threat"),
    (r"\b(?:unauthorized (?:login|access|transaction|activity))\b", "security_alert_pressure"),
    (r"\b(?:verify (?:your )?(?:account|identity|billing|credentials|password)|update your payment)\b", "credential_harvest_prompt"),
    (r"\b(?:click (?:here|below|the link)|login to restore|avoid suspension)\b", "coercive_call_to_action"),
    (r"\b(?:wire transfer|gift card|crypto|bitcoin|invoice payment|overdue payment)\b", "financial_pressure_tactic"),
]


@dataclass
class UrgencyAnalysisResult:
    detected_phrases: List[str] = field(default_factory=list)
    categories_triggered: List[str] = field(default_factory=list)
    urgency_score: float = 0.0
    flags: List[str] = field(default_factory=list)


class UrgencyDetector:
    def __init__(self):
        pass

    def analyze(self, text: str) -> UrgencyAnalysisResult:
        if not text:
            return UrgencyAnalysisResult()

        text_lower = text.lower()
        detected_phrases = []
        categories = set()

        for pattern, category in URGENCY_PATTERNS:
            matches = re.findall(pattern, text_lower)
            if matches:
                categories.add(category)
                for match in matches:
                    if match not in detected_phrases:
                        detected_phrases.append(match)

        # Calculate score based on density and categories triggered
        category_weight = len(categories) * 0.25
        count_weight = min(0.3, len(detected_phrases) * 0.1)
        raw_score = min(1.0, category_weight + count_weight)

        flags = []
        if categories:
            flags.append(f"Detected {len(categories)} urgency/pressure categories: {', '.join(sorted(categories))}")
        if "account_status_threat" in categories:
            flags.append("High risk pressure tactic: Threat of account suspension or termination")

        return UrgencyAnalysisResult(
            detected_phrases=detected_phrases,
            categories_triggered=list(categories),
            urgency_score=raw_score,
            flags=flags
        )
