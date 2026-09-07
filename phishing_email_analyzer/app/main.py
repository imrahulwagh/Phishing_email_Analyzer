import sys
from pathlib import Path
from typing import Optional, List
from fastapi import FastAPI, File, UploadFile, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv

# Ensure parent path is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

load_dotenv()

from ingestion.eml_parser import parse_eml
from scoring.risk_scorer import RiskScorer

app = FastAPI(title="Phishing Email Analyzer UI", version="1.0.0")

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

scorer = RiskScorer()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.post("/api/analyze")
async def analyze_eml(
    file: UploadFile = File(...),
    threshold: Optional[float] = Form(0.65),
    weight_header: Optional[float] = Form(0.35),
    weight_image: Optional[float] = Form(0.25),
    weight_content: Optional[float] = Form(0.40)
):
    if not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted.")

    try:
        content = await file.read()
        parsed_email = parse_eml(content)

        custom_scorer = RiskScorer(
            weight_header=weight_header or 0.35,
            weight_image=weight_image or 0.25,
            weight_content=weight_content or 0.40,
            risk_threshold=threshold or 0.65
        )

        assessment = custom_scorer.evaluate_email(parsed_email)

        return {
            "filename": file.filename,
            "subject": parsed_email.subject,
            "sender": parsed_email.from_header,
            "date": parsed_email.date,
            "body_snippet": (parsed_email.body_plain or parsed_email.body_html)[:300],
            "analysis": assessment.to_dict()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze email: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
