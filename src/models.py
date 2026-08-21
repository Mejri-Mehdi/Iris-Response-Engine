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
    relationship,
    sessionmaker,
    Session,
)


# ---------------------------------------------------------------------------
# Base class (SQLAlchemy 2.0 style)
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------

class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        String(20), unique=True, index=True
    )  # format: INC-YYYY-NNNN
    type: Mapped[str] = mapped_column(String(50))  # malware, phishing, etc.
    severity: Mapped[str] = mapped_column(String(20))  # critical, high, medium, low
    status: Mapped[str] = mapped_column(
        String(20), default="open"
    )  # open, triaging, containing, eradicating, recovering, closed
    timestamp: Mapped[datetime.datetime] = mapped_column(DateTime)  # reported time
    affected_host: Mapped[str] = mapped_column(String(100))
    affected_user: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_logs: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # stored as JSON string
    current_step: Mapped[int] = mapped_column(Integer, default=0)
    playbook_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    context: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string – shared state
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

    # Relationships
    executions = relationship("PlaybookExecution", back_populates="incident", cascade="all, delete-orphan")
    evidence = relationship("Evidence", back_populates="incident", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Incident {self.incident_id} ({self.status})>"


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"))
    step_name: Mapped[str] = mapped_column(String(100))
    step_action: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(
        String(20), default="pending"
    )  # pending, running, completed, failed, skipped
    started_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime, nullable=True
    )
    completed_at: Mapped[Optional[datetime.datetime]] = mapped_column(
        DateTime, nullable=True
    )
    result: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string
    mock: Mapped[bool] = mapped_column(Boolean, default=True)
    
    incident = relationship("Incident", back_populates="executions")


    def __repr__(self):
        return f"<PlaybookExecution step='{self.step_name}' status='{self.status}'>"


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"))
    evidence_type: Mapped[str] = mapped_column(
        String(50)
    )  # log, hash, ip_lookup, screenshot, memory_dump
    source: Mapped[str] = mapped_column(String(100))  # where it came from
    data: Mapped[str] = mapped_column(Text)  # the actual evidence content
    collected_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow
    )

    incident = relationship("Incident", back_populates="evidence")

    
    def __repr__(self):
        return f"<Evidence {self.evidence_type} from {self.source}>"


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def get_engine(db_path: str = "iris.db"):
    """
    Creates and returns a SQLite engine.
    The 'check_same_thread' flag allows use in multi-threaded contexts (FastAPI).
    """
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        echo=False,  # set to True for debugging SQL
    )
    return engine


def init_db(engine):
    """
    Creates all tables in the database.
    """
    Base.metadata.create_all(engine)


def get_session(engine) -> sessionmaker[Session]:
    """
    Returns a sessionmaker factory bound to the given engine.
    Call it to obtain a new SQLAlchemy Session, e.g.:
        Session = get_session(engine)
        with Session() as session:
            ...
    """
    return sessionmaker(bind=engine)