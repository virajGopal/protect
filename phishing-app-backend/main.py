from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from scanner import extract_features, calculate_risk_score

app = FastAPI(title="Phishing Detection API")

# Setup CORS for the frontend app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

class URLRequest(BaseModel):
    url: str

@app.get("/")
def read_root():
    return {"message": "Welcome to the Phishing Detection API. Use /api/scan to scan a URL."}

@app.post("/api/scan")
def scan_url(request: URLRequest):
    if not request.url:
        raise HTTPException(status_code=400, detail="URL is required")

    features = extract_features(request.url)
    risk_assessment = calculate_risk_score(features)

    return {
        "url": request.url,
        "features": features,
        "assessment": risk_assessment
    }
