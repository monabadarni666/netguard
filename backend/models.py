from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Integer,
    String,
)

from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from backend.database import Base


class SecurityEvent(Base):

    __tablename__ = "security_events"


    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )


    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(
            timezone.utc
        ),
    )


    prediction: Mapped[str] = mapped_column(
        String(20)
    )


    risk_score: Mapped[float] = mapped_column(
        Float
    )


    severity: Mapped[str] = mapped_column(
        String(20)
    )


    protocol: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )


    service: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )


    state: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )


    duration: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )


    source_bytes: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )


    destination_bytes: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )


    # ======================================================
    # V3 Anomaly Detection Fields
    # ======================================================

    is_anomaly: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
    )


    anomaly_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )


    anomaly_threshold: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )


    detection_source: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
