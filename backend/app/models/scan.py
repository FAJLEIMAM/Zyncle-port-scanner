from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    target: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="pending",
    )

    profile: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="common",
    )

    vulnerability_profile: Mapped[str] = mapped_column(
    String(20),
    nullable=False,
    default="lightweight",
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    hosts = relationship(
        "Host",
        back_populates="scan",
        cascade="all, delete-orphan",
    )