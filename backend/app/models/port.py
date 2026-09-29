from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    host_id: Mapped[int] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"),
        nullable=False,
    )

    port_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    protocol: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="tcp",
    )

    state: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="unknown",
    )

    host = relationship(
        "Host",
        back_populates="ports",
    )

    service = relationship(
    	"Service",
    	back_populates="port",
    	uselist=False,
    	cascade="all, delete-orphan",
    )