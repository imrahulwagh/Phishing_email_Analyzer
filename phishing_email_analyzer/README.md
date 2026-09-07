# Modular Python Phishing Email Analyzer

A multi-tiered, modular Python-based security tool to analyze `.eml` email files and calculate a weighted risk score (0.0 - 1.0) using **Header Analysis**, **Perceptual Image Logo Phishing Detection**, and **Content / NLP Analysis**.

Includes a **CLI entry point**, **JSON report exporter**, **unit test suite**, and a **Modern Light-themed Web UI Dashboard** (FastAPI + Tailwind CSS).

---

## 🛠️ Architecture & Detection Modules

1. **Header Analysis (`/header_analysis`)**:
   - Parses `.eml` MIME structure.
   - Verifies **SPF**, **DKIM**, and **DMARC** authentication statuses.
   - Flags **From** vs. **Reply-To** and **From** vs. **Return-Path** domain mismatches.
   - Checks lookalike / typosquatting domain patterns (e.g. `paypa1.com`, `rnicrosoft.com`).
   - Integrates **MSTICPy** & API keys for sender IP and domain reputation lookups.

2. **Image / Logo Phishing Detection (`/image_analysis`)**:
   - Extracts embedded attachments and inline CID image objects from emails.
   - Computes perceptual hashes (`phash`, `dhash`) using `ImageHash` and `Pillow`.
   - Compares extracted images against reference brand logos (`image_analysis/reference_logos`).
   - Flags unauthorized brand logo usage when emails originating from external domains contain official brand logos.

3. **Content / NLP Analysis (`/content_analysis`)**:
   - Strips and normalizes HTML text.
   - **Link Mismatch Inspector**: Detects visual hyperlink text domain vs actual `href` destination mismatches (e.g., text displays `https://paypal.com` but link leads to `http://evil-phish.net`).
   - **Urgency Language Detector**: Identifies psychological pressure tactics, threats of account termination, and immediate call-to-action prompts.
   - **TF-IDF + Logistic Regression ML Classifier**: Predicts phishing probability based on textual content.

4. **Weighted Scoring Engine (`/scoring`)**:
   - Combines normalized sub-scores:
     $$Score_{total} = (W_{header} \cdot S_{header}) + (W_{image} \cdot S_{image}) + (W_{content} \cdot S_{content})$$
   - Default Weights: Header (0.35), Image (0.25), Content (0.40).
   - Configurable risk threshold (default `0.65`) assigning verdicts: `HIGH_RISK_PHISHING`, `SUSPICIOUS`, or `LEGITIMATE`.

---

## 📁 Project Structure

```
phishing_email_analyzer/
├── ingestion/               # EML parser extracting headers, body, links, images
│   ├── __init__.py
│   └── eml_parser.py
├── header_analysis/         # SPF/DKIM/DMARC & MSTICPy threat intel reputation
│   ├── __init__.py
│   ├── header_analyzer.py
│   └── reputation_lookup.py
├── image_analysis/          # Perceptual image hashing & brand logo detection
│   ├── __init__.py
│   ├── logo_detector.py
│   └── reference_logos/     # Local reference logos (PayPal, Microsoft, etc.)
├── content_analysis/        # Text cleaning, link mismatch, urgency & ML classifier
│   ├── __init__.py
│   ├── text_cleaner.py
│   ├── urgency_detector.py
│   ├── nlp_classifier.py
│   └── train_model.py
├── scoring/                 # Weighted risk score aggregator & signal builder
│   ├── __init__.py
│   └── risk_scorer.py
├── app/                     # Modern Light-Themed Web UI (FastAPI + Tailwind)
│   ├── __init__.py
│   ├── main.py
│   └── templates/
│       └── index.html
├── tests/                   # Pytest unit tests & sample .eml fixtures
│   ├── fixtures/
│   │   ├── legitimate.eml
│   │   └── phishing.eml
│   ├── test_ingestion.py
│   ├── test_header_analysis.py
│   ├── test_image_analysis.py
│   ├── test_content_analysis.py
│   └── test_scoring.py
├── cli.py                   # CLI entry point for batch .eml processing
├── requirements.txt
├── .env.example
└── README.md
```

---

## 🚀 Quick Start

### 1. Installation
```bash
pip install -r requirements.txt
```

### 2. Configure Environment Variables (Optional)
Copy `.env.example` to `.env` and set API keys:
```bash
VT_API_KEY=your_virustotal_key
OTX_API_KEY=your_otx_key
MSTICPYCONFIG=./msticpyconfig.yaml
```

### 3. Run CLI Email Folder Analyzer
Analyze a folder of `.eml` files and export a JSON report:
```bash
python cli.py --input tests/fixtures --output report.json --threshold 0.65
```

### 4. Launch Modern Web UI Dashboard
Start the light-themed FastAPI Web UI:
```bash
python app/main.py
# Or using uvicorn directly:
# uvicorn app.main:app --reload
```
Open your browser at: `http://127.0.0.1:8000`

### 5. Run Unit Tests
Execute full test suite using `pytest`:
```bash
pytest tests/ -v
```
