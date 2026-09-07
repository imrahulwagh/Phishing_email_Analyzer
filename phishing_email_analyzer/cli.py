import sys
import os
import json
import argparse
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

from ingestion.eml_parser import parse_eml
from scoring.risk_scorer import RiskScorer


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Email Analyzer CLI - Process .eml files and generate JSON security reports."
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Path to folder containing .eml files or path to a single .eml file."
    )
    parser.add_argument(
        "--output", "-o",
        default="phishing_analysis_report.json",
        help="Output path for JSON report (default: phishing_analysis_report.json)."
    )
    parser.add_argument(
        "--threshold", "-t",
        type=float,
        default=0.65,
        help="Custom risk threshold between 0.0 and 1.0 (default: 0.65)."
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input path '{args.input}' does not exist.")
        sys.exit(1)

    eml_files = []
    if input_path.is_file():
        if input_path.suffix.lower() == ".eml":
            eml_files.append(input_path)
    elif input_path.is_dir():
        eml_files = list(input_path.glob("*.eml")) + list(input_path.glob("**/*.eml"))

    if not eml_files:
        print(f"No .eml files found in '{args.input}'.")
        sys.exit(0)

    print(f"Found {len(eml_files)} .eml file(s) for analysis. Processing...")

    scorer = RiskScorer(risk_threshold=args.threshold)
    results = []

    for eml_file in eml_files:
        try:
            parsed_email = parse_eml(eml_file)
            assessment = scorer.evaluate_email(parsed_email)
            file_report = {
                "file_path": str(eml_file),
                "filename": eml_file.name,
                "subject": parsed_email.subject,
                "sender": parsed_email.from_header,
                "date": parsed_email.date,
                "analysis": assessment.to_dict()
            }
            results.append(file_report)
            status_symbol = "[PHISHING]" if assessment.verdict == "HIGH_RISK_PHISHING" else ("[SUSPICIOUS]" if assessment.verdict == "SUSPICIOUS" else "[CLEAN]")
            safe_subject = parsed_email.subject.encode('ascii', errors='ignore').decode('ascii')
            print(f"{status_symbol} {eml_file.name} - Score: {assessment.overall_risk_score:.2f} (Subject: {safe_subject[:40]}...)")
        except Exception as e:
            print(f"Error processing {eml_file.name}: {e}")

    report = {
        "summary": {
            "total_analyzed": len(results),
            "high_risk_count": sum(1 for r in results if r["analysis"]["verdict"] == "HIGH_RISK_PHISHING"),
            "suspicious_count": sum(1 for r in results if r["analysis"]["verdict"] == "SUSPICIOUS"),
            "legitimate_count": sum(1 for r in results if r["analysis"]["verdict"] == "LEGITIMATE"),
            "risk_threshold": args.threshold
        },
        "emails": results
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=lambda o: int(o) if hasattr(o, 'item') else str(o))

    print(f"\nAnalysis complete! JSON report exported to '{out_path.resolve()}'")


if __name__ == "__main__":
    main()
