from pathlib import Path
import json

import joblib
import pandas as pd

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy import select, func

from backend.database import SessionLocal
from backend.models import SecurityEvent


# ==========================================================
# Paths
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent.parent


# Full 42-feature model
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


# Live network model
LIVE_MODEL_PATH = (
    BASE_DIR
    / "ml"
    / "models"
    / "live_intrusion_model.joblib"
)

LIVE_CONFIG_PATH = (
    BASE_DIR
    / "ml"
    / "models"
    / "live_model_config.json"
)


# ==========================================================
# Load Models
# ==========================================================

model = joblib.load(
    MODEL_PATH
)

with open(
    CONFIG_PATH,
    "r"
) as file:
    config = json.load(
        file
    )


live_model = joblib.load(
    LIVE_MODEL_PATH
)

with open(
    LIVE_CONFIG_PATH,
    "r"
) as file:
    live_config = json.load(
        file
    )


# ==========================================================
# FastAPI Application
# ==========================================================

app = FastAPI(
    title="AI Cybersecurity Platform",
    description="AI-powered Network Intrusion Detection System",
    version="1.0.0"
)


# ==========================================================
# CORS
# ==========================================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],
)


# ==========================================================
# Severity - Full Dataset Model
# ==========================================================

def get_severity(
    risk_score: float
) -> str:

    if risk_score < 55:
        return "LOW"

    elif risk_score < 70:
        return "MEDIUM"

    elif risk_score < 85:
        return "HIGH"

    else:
        return "CRITICAL"


# ==========================================================
# Severity - Live Network Model
# ==========================================================

def get_live_severity(
    risk_score: float
) -> str:

    if risk_score < 50:
        return "LOW"

    elif risk_score < 70:
        return "MEDIUM"

    elif risk_score < 85:
        return "HIGH"

    else:
        return "CRITICAL"


# ==========================================================
# Root
# ==========================================================

@app.get("/")
def root():

    return {
        "message":
            "AI Cybersecurity Platform API",

        "status":
            "running"
    }


# ==========================================================
# Health
# ==========================================================

@app.get("/health")
def health():

    return {

        "status":
            "healthy",

        "full_model_loaded":
            True,

        "live_model_loaded":
            True,

        "full_model":
            config["model"],

        "live_model":
            live_config["model"],

        "threshold":
            config["threshold"],

        "number_of_features":
            len(
                config[
                    "feature_columns"
                ]
            ),

        "live_number_of_features":
            len(
                live_config[
                    "feature_columns"
                ]
            )
    }


# ==========================================================
# Full Model Features
# ==========================================================

@app.get("/features")
def features():

    return {

        "number_of_features":
            len(
                config[
                    "feature_columns"
                ]
            ),

        "features":
            config[
                "feature_columns"
            ]
    }


# ==========================================================
# Live Model Features
# ==========================================================

@app.get("/features/live")
def live_features():

    return {

        "number_of_features":
            len(
                live_config[
                    "feature_columns"
                ]
            ),

        "features":
            live_config[
                "feature_columns"
            ]
    }


# ==========================================================
# Full Model Prediction
# ==========================================================

@app.post("/predict")
def predict(
    payload: dict
):

    required_features = (
        config[
            "feature_columns"
        ]
    )


    missing_features = [

        feature

        for feature
        in required_features

        if feature
        not in payload
    ]


    if missing_features:

        raise HTTPException(

            status_code=422,

            detail={

                "message":
                    "Missing required features",

                "missing_features":
                    missing_features
            }
        )


    input_data = {

        feature:
            payload[feature]

        for feature
        in required_features
    }


    input_df = pd.DataFrame(
        [
            input_data
        ]
    )


    attack_score = float(

        model.predict_proba(
            input_df
        )[0][1]
    )


    threshold = float(
        config[
            "threshold"
        ]
    )


    prediction = (

        "ATTACK"

        if attack_score
        >= threshold

        else "NORMAL"
    )


    risk_score = round(
        attack_score
        * 100,
        2
    )


    severity = get_severity(
        risk_score
    )


    # ------------------------------------------------------
    # Save to PostgreSQL
    # ------------------------------------------------------

    with SessionLocal() as db:

        event = SecurityEvent(

            prediction=
                prediction,

            risk_score=
                risk_score,

            severity=
                severity,

            protocol=(
                str(
                    payload.get(
                        "proto"
                    )
                )

                if payload.get(
                    "proto"
                )
                is not None

                else None
            ),

            service=(
                str(
                    payload.get(
                        "service"
                    )
                )

                if payload.get(
                    "service"
                )
                is not None

                else None
            ),

            state=(
                str(
                    payload.get(
                        "state"
                    )
                )

                if payload.get(
                    "state"
                )
                is not None

                else None
            ),

            duration=(
                float(
                    payload.get(
                        "dur"
                    )
                )

                if payload.get(
                    "dur"
                )
                is not None

                else None
            ),

            source_bytes=(
                int(
                    payload.get(
                        "sbytes"
                    )
                )

                if payload.get(
                    "sbytes"
                )
                is not None

                else None
            ),

            destination_bytes=(
                int(
                    payload.get(
                        "dbytes"
                    )
                )

                if payload.get(
                    "dbytes"
                )
                is not None

                else None
            )
        )


        db.add(
            event
        )

        db.commit()

        db.refresh(
            event
        )

        event_id = (
            event.id
        )


    return {

        "event_id":
            event_id,

        "source":
            "DATASET_MODEL",

        "prediction":
            prediction,

        "risk_score":
            risk_score,

        "severity":
            severity,

        "threshold":
            threshold
    }


# ==========================================================
# Live Network Prediction
# ==========================================================

@app.post("/predict/live")
def predict_live(
    payload: dict
):

    required_features = (
        live_config[
            "feature_columns"
        ]
    )


    missing_features = [

        feature

        for feature
        in required_features

        if feature
        not in payload
    ]


    if missing_features:

        raise HTTPException(

            status_code=422,

            detail={

                "message":
                    "Missing live traffic features",

                "missing_features":
                    missing_features
            }
        )


    input_data = {

        feature:
            payload[feature]

        for feature
        in required_features
    }


    input_df = pd.DataFrame(
        [
            input_data
        ]
    )


    attack_probability = float(

        live_model.predict_proba(
            input_df
        )[0][1]
    )


    # Live model threshold
    threshold = 0.50


    prediction = (

        "ATTACK"

        if attack_probability
        >= threshold

        else "NORMAL"
    )


    risk_score = round(

        attack_probability
        * 100,

        2
    )


    # IMPORTANT:
    # Live model uses its own severity thresholds

    severity = get_live_severity(
        risk_score
    )


    # ------------------------------------------------------
    # Save Live Event to PostgreSQL
    # ------------------------------------------------------

    with SessionLocal() as db:

        event = SecurityEvent(

            prediction=
                prediction,

            risk_score=
                risk_score,

            severity=
                severity,

            protocol=(
                str(
                    payload.get(
                        "proto"
                    )
                )

                if payload.get(
                    "proto"
                )
                is not None

                else None
            ),

            service=
                None,

            state=
                None,

            duration=
                float(
                    payload.get(
                        "dur",
                        0
                    )
                ),

            source_bytes=
                int(
                    payload.get(
                        "sbytes",
                        0
                    )
                ),

            destination_bytes=
                int(
                    payload.get(
                        "dbytes",
                        0
                    )
                )
        )


        db.add(
            event
        )

        db.commit()

        db.refresh(
            event
        )

        event_id = (
            event.id
        )


    return {

        "event_id":
            event_id,

        "source":
            "LIVE_NETWORK",

        "prediction":
            prediction,

        "attack_probability":
            round(
                attack_probability,
                4
            ),

        "risk_score":
            risk_score,

        "severity":
            severity,

        "threshold":
            threshold
    }


# ==========================================================
# Recent Events
# ==========================================================

@app.get("/events")
def get_events(
    limit: int = 50
):

    with SessionLocal() as db:

        events = db.scalars(

            select(
                SecurityEvent
            )

            .order_by(
                SecurityEvent
                .timestamp
                .desc()
            )

            .limit(
                limit
            )

        ).all()


        return [

            {

                "id":
                    event.id,

                "timestamp":
                    event.timestamp
                    .isoformat(),

                "prediction":
                    event.prediction,

                "risk_score":
                    event.risk_score,

                "severity":
                    event.severity,

                "protocol":
                    event.protocol,

                "service":
                    event.service,

                "state":
                    event.state,

                "duration":
                    event.duration,

                "source_bytes":
                    event.source_bytes,

                "destination_bytes":
                    event.destination_bytes
            }

            for event
            in events
        ]


# ==========================================================
# Alerts
# ==========================================================

@app.get("/alerts")
def get_alerts(
    limit: int = 50
):

    with SessionLocal() as db:

        events = db.scalars(

            select(
                SecurityEvent
            )

            .where(
                SecurityEvent
                .prediction
                == "ATTACK"
            )

            .order_by(
                SecurityEvent
                .timestamp
                .desc()
            )

            .limit(
                limit
            )

        ).all()


        return [

            {

                "id":
                    event.id,

                "timestamp":
                    event.timestamp
                    .isoformat(),

                "risk_score":
                    event.risk_score,

                "severity":
                    event.severity,

                "protocol":
                    event.protocol,

                "service":
                    event.service,

                "state":
                    event.state
            }

            for event
            in events
        ]


# ==========================================================
# Statistics
# ==========================================================

@app.get("/statistics")
def get_statistics():

    with SessionLocal() as db:

        total_events = (

            db.scalar(

                select(
                    func.count()
                )

                .select_from(
                    SecurityEvent
                )
            )

            or 0
        )


        attack_events = (

            db.scalar(

                select(
                    func.count()
                )

                .select_from(
                    SecurityEvent
                )

                .where(
                    SecurityEvent
                    .prediction
                    == "ATTACK"
                )
            )

            or 0
        )


        normal_events = (

            db.scalar(

                select(
                    func.count()
                )

                .select_from(
                    SecurityEvent
                )

                .where(
                    SecurityEvent
                    .prediction
                    == "NORMAL"
                )
            )

            or 0
        )


        critical_events = (

            db.scalar(

                select(
                    func.count()
                )

                .select_from(
                    SecurityEvent
                )

                .where(
                    SecurityEvent
                    .severity
                    == "CRITICAL"
                )
            )

            or 0
        )


        average_risk = (

            db.scalar(

                select(

                    func.avg(
                        SecurityEvent
                        .risk_score
                    )
                )
            )

            or 0
        )


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
                    float(
                        average_risk
                    ),
                    2
                )
        }


# ==========================================================
# Severity Analytics
# ==========================================================

@app.get("/analytics/severity")
def severity_analytics():

    with SessionLocal() as db:

        results = db.execute(

            select(

                SecurityEvent
                .severity,

                func.count(
                    SecurityEvent.id
                )
            )

            .group_by(
                SecurityEvent
                .severity
            )

        ).all()


        return {

            severity:
                count

            for severity, count
            in results
        }


# ==========================================================
# Protocol Analytics
# ==========================================================

@app.get("/analytics/protocols")
def protocol_analytics():

    with SessionLocal() as db:

        results = db.execute(

            select(

                SecurityEvent
                .protocol,

                func.count(
                    SecurityEvent.id
                )
            )

            .group_by(
                SecurityEvent
                .protocol
            )

        ).all()


        return {

            (
                protocol
                if protocol
                else "Unknown"
            ):
                count

            for protocol, count
            in results
        }
