from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    service_id: Mapped[int] = mapped_column(
        ForeignKey("services.id", ondelete="CASCADE"),
        nullable=False,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    vulnerability_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    severity: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )

    cvss_score: Mapped[float | None] = mapped_column(
        nullable=True,
    )

    cwe_ids: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    cvss_metrics: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Risk classification
    risk_level: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )

    risk_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    source: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    matcher_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    
    evidence: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )

    service = relationship(
        "Service",
        back_populates="findings",
    )