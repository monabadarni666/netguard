from pathlib import Path
import json
import joblib
import pandas as pd

from fastapi import FastAPI, HTTPException


BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = BASE_DIR / "ml" / "models" / "intrusion_detection_model.joblib"
CONFIG_PATH = BASE_DIR / "ml" / "models" / "model_config.json"


# Load trained ML model
model = joblib.load(MODEL_PATH)

# Load model configuration
with open(CONFIG_PATH, "r") as file:
    config = json.load(file)


app = FastAPI(
    title="AI Cybersecurity Platform",
    description="AI-powered Network Intrusion Detection System",
    version="1.0.0"
)


def get_severity(risk_score: float) -> str:
    if risk_score < 55:
        return "LOW"
    elif risk_score < 70:
        return "MEDIUM"
    elif risk_score < 85:
        return "HIGH"
    else:
        return "CRITICAL"


@app.get("/")
def root():
    return {
        "message": "AI Cybersecurity Platform API",
        "status": "running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "model_loaded": True,
        "model": config["model"],
        "threshold": config["threshold"],
        "number_of_features": len(config["feature_columns"])
    }


@app.get("/features")
def features():
    return {
        "number_of_features": len(config["feature_columns"]),
        "features": config["feature_columns"]
    }


@app.post("/predict")
def predict(payload: dict):
    required_features = config["feature_columns"]

    missing_features = [
        feature
        for feature in required_features
        if feature not in payload
    ]

    if missing_features:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Missing required features",
                "missing_features": missing_features
            }
        )

    input_data = {
        feature: payload[feature]
        for feature in required_features
    }

    input_df = pd.DataFrame([input_data])

    attack_score = float(
        model.predict_proba(input_df)[0][1]
    )

    threshold = float(config["threshold"])

    prediction = (
        "ATTACK"
        if attack_score >= threshold
        else "NORMAL"
    )

    risk_score = round(attack_score * 100, 2)

    return {
        "prediction": prediction,
        "risk_score": risk_score,
        "severity": get_severity(risk_score),
        "threshold": threshold
    }
