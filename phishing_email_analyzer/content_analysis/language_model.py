import math
import re
from collections import Counter
from typing import Dict, List

from .text_cleaner import clean_text
from .train_model import SAMPLE_LEGITIMATE_TEXTS, SAMPLE_PHISHING_TEXTS


class MultinomialLanguageModel:
    """
    Simple unigram multinomial language model for IR Unit IV.

    It learns P(word | phishing) and P(word | legitimate) from the
    existing baseline email texts using Laplace smoothing.

    The returned score is a normalized phishing-language score from 0 to 1.
    This module is informational and does NOT change the existing risk score.
    """

    def __init__(self, alpha: float = 1.0):
        self.alpha = alpha
        self.phishing_counts = Counter()
        self.legitimate_counts = Counter()
        self.vocabulary = set()
        self.phishing_total = 0
        self.legitimate_total = 0
        self._train()

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        text = clean_text(text).lower()
        return re.findall(r"[a-z0-9]+(?:'[a-z]+)?", text)

    def _train(self) -> None:
        for text in SAMPLE_PHISHING_TEXTS:
            tokens = self._tokenize(text)
            self.phishing_counts.update(tokens)

        for text in SAMPLE_LEGITIMATE_TEXTS:
            tokens = self._tokenize(text)
            self.legitimate_counts.update(tokens)

        self.vocabulary = set(self.phishing_counts) | set(self.legitimate_counts)
        self.phishing_total = sum(self.phishing_counts.values())
        self.legitimate_total = sum(self.legitimate_counts.values())

    def _word_probability(self, word: str, counts: Counter, total: int) -> float:
        # Laplace/add-one smoothing prevents zero probability for unseen words.
        return (counts.get(word, 0) + self.alpha) / (
            total + self.alpha * len(self.vocabulary)
        )

    def analyze(self, text: str) -> Dict:
        tokens = self._tokenize(text)

        if not tokens or not self.vocabulary:
            return {
                "phishing_language_score": 0.0,
                "phishing_log_probability": 0.0,
                "legitimate_log_probability": 0.0,
                "top_phishing_terms": [],
                "model": "Unigram Multinomial Language Model"
            }

        phishing_log_prob = 0.0
        legitimate_log_prob = 0.0
        term_contributions = []

        for word in tokens:
            p_phish = self._word_probability(
                word, self.phishing_counts, self.phishing_total
            )
            p_legit = self._word_probability(
                word, self.legitimate_counts, self.legitimate_total
            )

            phishing_log_prob += math.log(p_phish)
            legitimate_log_prob += math.log(p_legit)

            # Positive log-ratio means this word is more associated with
            # the phishing language model than the legitimate model.
            log_ratio = math.log(p_phish / p_legit)
            term_contributions.append((word, log_ratio))

        # Average log likelihood ratio so long emails do not automatically
        # receive larger scores just because they contain more words.
        avg_log_ratio = (phishing_log_prob - legitimate_log_prob) / len(tokens)

        # Convert the log-ratio to a 0..1 score.
        phishing_score = 1.0 / (1.0 + math.exp(-avg_log_ratio))

        # Show the strongest phishing-associated words for explainability.
        unique_terms = {}
        for word, contribution in term_contributions:
            if contribution > 0:
                unique_terms[word] = max(unique_terms.get(word, 0.0), contribution)

        top_terms = sorted(
            unique_terms.items(), key=lambda item: item[1], reverse=True
        )[:5]

        return {
            "phishing_language_score": round(phishing_score, 4),
            "phishing_log_probability": round(phishing_log_prob, 4),
            "legitimate_log_probability": round(legitimate_log_prob, 4),
            "top_phishing_terms": [
                {"word": word, "log_ratio": round(score, 4)}
                for word, score in top_terms
            ],
            "model": "Unigram Multinomial Language Model"
        }
