# src/models.py
import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    create_engine,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    sessionmaker,
    Session,
    relationship,          # <-- added
)


class Base(DeclarativeBase):
    pass


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        String(20), unique=True, index=True
    )
    type: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="open")
    timestamp: Mapped[datetime.datetime] = mapped_column(DateTime)
    affected_host: Mapped[str] = mapped_column(String(100))
    affected_user: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_logs: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    current_step: Mapped[int] = mapped_column(Integer, default=0)
    playbook_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    context: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime,
        default=datetime.datetime.utcnow,
        onupdate=datetime.datetime.utcnow,
    )
    resolved_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime, nullable=True
    )

    # Relationships (added to fix tests)
    executions: Mapped[list["PlaybookExecution"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Incident {self.incident_id} ({self.status})>"


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"))
    step_name: Mapped[str] = mapped_column(String(100))
    step_action: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    started_at: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime.datetime]] = mapped_column(DateTime, nullable=True)
    result: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mock: Mapped[bool] = mapped_column(Boolean, default=True)

    # Relationship back to Incident (added)
    incident: Mapped["Incident"] = relationship(back_populates="executions")

    def __repr__(self):
        return f"<PlaybookExecution step='{self.step_name}' status='{self.status}'>"


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"))
    evidence_type: Mapped[str] = mapped_column(String(50))
    source: Mapped[str] = mapped_column(String(100))
    data: Mapped[str] = mapped_column(Text)
    collected_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow
    )

    # Relationship back to Incident (added)
    incident: Mapped["Incident"] = relationship(back_populates="evidence")

    def __repr__(self):
        return f"<Evidence {self.evidence_type} from {self.source}>"


def get_engine(db_path: str = "iris.db"):
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        echo=False,
    )
    return engine


def init_db(engine):
    Base.metadata.create_all(engine)


def get_session(engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine)