import enum
from datetime import datetime

from sqlalchemy import (
    Column, Integer, String, Float, DateTime, ForeignKey, Text, Enum, Boolean
)
from sqlalchemy.orm import relationship

from app.models.database import Base


class UserRole(str, enum.Enum):
    ANALYST = "analyst"
    ADMIN = "admin"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    role = Column(Enum(UserRole), default=UserRole.ANALYST)
    created_at = Column(DateTime, default=datetime.utcnow)

    projects = relationship("Project", back_populates="owner")


class Project(Base):
    """
    A 'Project' represents an authorized target application under test.
    Authorization must be confirmed before any scan can be launched
    (see is_authorized flag + docs/scope_and_authorization.md).
    """
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    target_base_url = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    is_authorized = Column(Boolean, default=False)  # must be explicitly set true
    authorization_note = Column(Text, nullable=True)  # who approved, scope, date
    owner_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="projects")
    scans = relationship("ScanRun", back_populates="project")


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    categories = Column(String, nullable=True)  # comma-separated list requested
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scan_runs.id"))
    check_id = Column(String, nullable=False)
    category = Column(String, nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    risk_score = Column(Float, nullable=False)
    affected_component = Column(String, nullable=True)
    evidence = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("ScanRun", back_populates="findings")
