import pickle
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


SAMPLE_LEGITIMATE_TEXTS = [
    "Hi Team, please find attached the monthly project status report for Q3.",
    "Hey John, let's schedule our quarterly 1-on-1 sync for tomorrow at 10 AM.",
    "Thank you for attending the engineering webinar. The slides and recording are available here.",
    "Your weekly digest from GitHub: 5 pull requests merged and 3 open issues.",
    "Reminder: Team lunch is scheduled for Friday at 12:30 PM in the main cafeteria.",
    "Here is your invoice #48192 from Acme Cloud Services for August usage.",
    "Sprint planning meeting notes and action items from today's discussion.",
    "Your flight booking confirmation for flight AA-104 to San Francisco.",
    "Happy birthday Sarah! Hope you have a wonderful celebration today.",
    "The codebase review for pull request #42 is complete. Approved for deployment."
]

SAMPLE_PHISHING_TEXTS = [
    "URGENT: Your PayPal account has been suspended due to suspicious activity. Verify now to restore access.",
    "SECURITY ALERT: Unauthorized login attempt detected on your bank account. Click here to confirm identity immediately.",
    "Your Microsoft 365 password expires in 2 hours. Update payment and password to avoid service termination.",
    "Final Notice: Your parcel delivery failed. Click the link to update your shipping address within 24 hours.",
    "ATTENTION: Suspicious wire transfer initiated. Verify your credentials immediately or funds will be locked.",
    "Account Warning: Your Apple ID is temporarily restricted. Log in to verify your billing details.",
    "Urgent Action Required: Confirm your tax refund of $1,250 by entering your social security number.",
    "Security Notification: Unusual activity from unknown IP address. Click here immediately to secure account.",
    "Your Netflix payment was declined. Update credit card immediately to avoid account cancellation.",
    "Important message from HR: Direct deposit payment failed. Verify your banking details right now."
]


def train_baseline_model(save_path: str = None) -> Pipeline:
    """
    Trains a TF-IDF + Logistic Regression pipeline on labeled email text data.
    """
    if save_path is None:
        save_path = Path(__file__).parent / "phishing_model.pkl"

    X = SAMPLE_LEGITIMATE_TEXTS + SAMPLE_PHISHING_TEXTS
    y = [0] * len(SAMPLE_LEGITIMATE_TEXTS) + [1] * len(SAMPLE_PHISHING_TEXTS)

    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1, 2), max_features=3000, lowercase=True)),
        ('clf', LogisticRegression(C=2.0, max_iter=200))
    ])

    pipeline.fit(X, y)

    target_file = Path(save_path)
    target_file.parent.mkdir(parents=True, exist_ok=True)
    with open(target_file, "wb") as f:
        pickle.dump(pipeline, f)

    return pipeline


if __name__ == "__main__":
    model = train_baseline_model()
    print("Baseline TF-IDF Logistic Regression phishing model successfully trained and saved!")
