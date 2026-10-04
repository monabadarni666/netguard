from pathlib import Path
import json

import joblib
import pandas as pd

from fastapi import FastAPI, HTTPException
from sqlalchemy import select, func

from backend.database import SessionLocal
from backend.models import SecurityEvent


# --------------------------------------------------
# Paths
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = (
    BASE_DIR
    / "ml"
    / "models"
    / "intrusion_detection_model.joblib"
)

CONFIG_PATH = (
    BASE_DIR
    / "ml"
    / "models"
    / "model_config.json"
)


# --------------------------------------------------
# Load ML model and configuration
# --------------------------------------------------

model = joblib.load(MODEL_PATH)

with open(CONFIG_PATH, "r") as file:
    config = json.load(file)


# --------------------------------------------------
# FastAPI application
# --------------------------------------------------

app = FastAPI(
    title="AI Cybersecurity Platform",
    description="AI-powered Network Intrusion Detection System",
    version="1.0.0"
)


# --------------------------------------------------
# Helper functions
# --------------------------------------------------

def get_severity(risk_score: float) -> str:

    if risk_score < 55:
        return "LOW"

    elif risk_score < 70:
        return "MEDIUM"

    elif risk_score < 85:
        return "HIGH"

    else:
        return "CRITICAL"


# --------------------------------------------------
# Root
# --------------------------------------------------

@app.get("/")
def root():

    return {
        "message": "AI Cybersecurity Platform API",
        "status": "running"
    }


# --------------------------------------------------
# Health check
# --------------------------------------------------

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "model_loaded": True,
        "model": config["model"],
        "threshold": config["threshold"],
        "number_of_features": len(
            config["feature_columns"]
        )
    }


# --------------------------------------------------
# Model features
# --------------------------------------------------

@app.get("/features")
def features():

    return {
        "number_of_features": len(
            config["feature_columns"]
        ),
        "features": config["feature_columns"]
    }


# --------------------------------------------------
# AI prediction
# --------------------------------------------------

@app.post("/predict")
def predict(payload: dict):

    required_features = config["feature_columns"]

    # Check for missing features
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


    # Keep only features expected by the ML model
    input_data = {
        feature: payload[feature]
        for feature in required_features
    }


    # Convert request into DataFrame
    input_df = pd.DataFrame(
        [input_data]
    )


    # Predict attack probability
    attack_score = float(
        model.predict_proba(input_df)[0][1]
    )


    # Load selected threshold
    threshold = float(
        config["threshold"]
    )


    # Final prediction
    prediction = (
        "ATTACK"
        if attack_score >= threshold
        else "NORMAL"
    )


    # Convert probability into risk score
    risk_score = round(
        attack_score * 100,
        2
    )


    # Determine severity
    severity = get_severity(
        risk_score
    )


    # --------------------------------------------------
    # Save event to PostgreSQL
    # --------------------------------------------------

    with SessionLocal() as db:

        event = SecurityEvent(

            prediction=prediction,

            risk_score=risk_score,

            severity=severity,

            protocol=(
                str(payload.get("proto"))
                if payload.get("proto") is not None
                else None
            ),

            service=(
                str(payload.get("service"))
                if payload.get("service") is not None
                else None
            ),

            state=(
                str(payload.get("state"))
                if payload.get("state") is not None
                else None
            ),

            duration=(
                float(payload.get("dur"))
                if payload.get("dur") is not None
                else None
            ),

            source_bytes=(
                int(payload.get("sbytes"))
                if payload.get("sbytes") is not None
                else None
            ),

            destination_bytes=(
                int(payload.get("dbytes"))
                if payload.get("dbytes") is not None
                else None
            )
        )


        db.add(event)

        db.commit()

        db.refresh(event)

        event_id = event.id


    # Return AI result
    return {
        "event_id": event_id,
        "prediction": prediction,
        "risk_score": risk_score,
        "severity": severity,
        "threshold": threshold
    }


# --------------------------------------------------
# Get security events
# --------------------------------------------------

@app.get("/events")
def get_events(limit: int = 50):

    with SessionLocal() as db:

        events = db.scalars(

            select(SecurityEvent)

            .order_by(
                SecurityEvent.timestamp.desc()
            )

            .limit(limit)

        ).all()


        return [

            {
                "id": event.id,

                "timestamp": (
                    event.timestamp.isoformat()
                ),

                "prediction": event.prediction,

                "risk_score": event.risk_score,

                "severity": event.severity,

                "protocol": event.protocol,

                "service": event.service,

                "state": event.state,

                "duration": event.duration,

                "source_bytes": event.source_bytes,

                "destination_bytes":
                    event.destination_bytes
            }

            for event in events
        ]


# --------------------------------------------------
# Get attack alerts
# --------------------------------------------------

@app.get("/alerts")
def get_alerts(limit: int = 50):

    with SessionLocal() as db:

        events = db.scalars(

            select(SecurityEvent)

            .where(
                SecurityEvent.prediction
                == "ATTACK"
            )

            .order_by(
                SecurityEvent.timestamp.desc()
            )

            .limit(limit)

        ).all()


        return [

            {
                "id": event.id,

                "timestamp": (
                    event.timestamp.isoformat()
                ),

                "risk_score": event.risk_score,

                "severity": event.severity,

                "protocol": event.protocol,

                "service": event.service,

                "state": event.state
            }

            for event in events
        ]


# --------------------------------------------------
# Security statistics
# --------------------------------------------------

@app.get("/statistics")
def get_statistics():

    with SessionLocal() as db:

        total_events = db.scalar(

            select(func.count())

            .select_from(
                SecurityEvent
            )

        ) or 0


        attack_events = db.scalar(

            select(func.count())

            .select_from(
                SecurityEvent
            )

            .where(
                SecurityEvent.prediction
                == "ATTACK"
            )

        ) or 0


        normal_events = db.scalar(

            select(func.count())

            .select_from(
                SecurityEvent
            )

            .where(
                SecurityEvent.prediction
                == "NORMAL"
            )

        ) or 0


        critical_events = db.scalar(

            select(func.count())

            .select_from(
                SecurityEvent
            )

            .where(
                SecurityEvent.severity
                == "CRITICAL"
            )

        ) or 0


        average_risk = db.scalar(

            select(
                func.avg(
                    SecurityEvent.risk_score
                )
            )

        ) or 0


        return {

            "total_events":
                total_events,

            "attack_events":
                attack_events,

            "normal_events":
                normal_events,

            "critical_events":
                critical_events,

            "average_risk_score":
                round(
                    float(average_risk),
                    2
                )
        }
