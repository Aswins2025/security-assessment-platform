from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, EmailStr, field_validator


# ---------- Auth ----------
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None


class UserOut(BaseModel):
    id: int
    email: EmailStr
    full_name: Optional[str] = None
    role: str

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ---------- Projects ----------
class ProjectCreate(BaseModel):
    name: str
    target_base_url: str
    description: Optional[str] = None
    is_authorized: bool
    authorization_note: Optional[str] = None

    @field_validator("is_authorized")
    @classmethod
    def must_be_authorized(cls, v):
        if not v:
            raise ValueError(
                "You must confirm written authorization to test this target "
                "before a project can be created."
            )
        return v


class ProjectOut(BaseModel):
    id: int
    name: str
    target_base_url: str
    description: Optional[str] = None
    is_authorized: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ---------- Scans ----------
class ScanCreate(BaseModel):
    project_id: int
    categories: List[str] = []  # empty = run all categories


class FindingOut(BaseModel):
    id: int
    check_id: str
    category: str
    title: str
    severity: str
    risk_score: float
    affected_component: Optional[str]
    evidence: Optional[str]
    recommendation: Optional[str]

    class Config:
        from_attributes = True


class ScanOut(BaseModel):
    id: int
    project_id: int
    status: str
    categories: Optional[str]
    started_at: datetime
    completed_at: Optional[datetime]
    error_message: Optional[str] = None
    findings: List[FindingOut] = []

    class Config:
        from_attributes = True


class ScanSummary(BaseModel):
    id: int
    project_id: int
    status: str
    started_at: datetime
    completed_at: Optional[datetime]
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int

    class Config:
        from_attributes = True
