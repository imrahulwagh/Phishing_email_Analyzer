import os
import pickle
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from pathlib import Path
from ingestion.eml_parser import ParsedEmail
from .text_cleaner import clean_text, check_link_mismatches
from .urgency_detector import UrgencyDetector
from .language_model import MultinomialLanguageModel


@dataclass
class NLPAnalysisResult:
    ml_phishing_probability: float
    urgency_score: float
    has_link_mismatches: bool
    link_mismatches: List[Dict[str, Any]]
    urgency_phrases: List[str]
    combined_content_risk_score: float
    language_model_result: Dict[str, Any]
    flags: List[str] = field(default_factory=list)


class ContentNLPClassifier:
    def __init__(self, model_path: Optional[str] = None):
        if model_path is None:
            model_path = Path(__file__).parent / "phishing_model.pkl"
        self.model_path = Path(model_path)
        self.pipeline = None
        self.urgency_detector = UrgencyDetector()
        self.language_model = MultinomialLanguageModel()
        self._load_or_train_fallback()

    def _load_or_train_fallback(self):
        """Loads serialized model or trains baseline pipeline if missing."""
        if self.model_path.exists():
            try:
                with open(self.model_path, "rb") as f:
                    self.pipeline = pickle.load(f)
                return
            except Exception:
                pass
        
        # Trigger inline baseline model creation if model artifact missing
        from .train_model import train_baseline_model
        self.pipeline = train_baseline_model(save_path=str(self.model_path))

    def predict_text(self, text: str) -> float:
        cleaned = clean_text(text)
        if not cleaned or not self.pipeline:
            return 0.0
        try:
            proba = self.pipeline.predict_proba([cleaned])[0][1]
            return float(proba)
        except Exception:
            return 0.0

    def analyze(self, email_data: ParsedEmail) -> NLPAnalysisResult:
        full_text = (email_data.subject + " " + email_data.body_plain + " " + email_data.body_html).strip()

        ml_prob = self.predict_text(full_text)
        language_model_result = self.language_model.analyze(full_text)
        urgency_res = self.urgency_detector.analyze(full_text)
        link_mismatches = check_link_mismatches(email_data.links)

        flags = []
        flags.extend(urgency_res.flags)

        if ml_prob > 0.65:
            flags.append(f"NLP ML Classifier detected phishing language (Probability: {ml_prob:.2%})")

        if link_mismatches:
            for mismatch in link_mismatches:
                flags.append(
                    f"Mismatched Hyperlink: Displayed text domain '{mismatch['displayed_domain']}' leads to actual destination '{mismatch['actual_domain']}'"
                )

        # Combined Content Risk Calculation
        mismatch_penalty = 0.50 if link_mismatches else 0.0
        combined = min(1.0, (ml_prob * 0.45) + (urgency_res.urgency_score * 0.25) + mismatch_penalty)

        return NLPAnalysisResult(
            ml_phishing_probability=ml_prob,
            urgency_score=urgency_res.urgency_score,
            has_link_mismatches=len(link_mismatches) > 0,
            link_mismatches=link_mismatches,
            urgency_phrases=urgency_res.detected_phrases,
            combined_content_risk_score=combined,
            language_model_result=language_model_result,
            flags=flags
        )
