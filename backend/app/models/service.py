from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Service(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    port_id: Mapped[int] = mapped_column(
        ForeignKey("ports.id", ondelete="CASCADE"),
        nullable=False,
    )

    service_name: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    product: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    version: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    cpe: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    confidence: Mapped[int | None] = mapped_column(
        nullable=True,
    )

    banner: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    port = relationship(
   	"Port",
    	back_populates="service",
    )

    findings = relationship(
    	"Finding",
    	back_populates="service",
    	cascade="all, delete-orphan",
    )