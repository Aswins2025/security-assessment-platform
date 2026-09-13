from typing import List

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session

from app.models.database import get_db
from app.models.models import Project, ScanRun, ScanStatus, User
from app.routers.deps import get_current_user
from app.scanners.runner import execute_scan
from app.schemas import (
    ProjectCreate, ProjectOut, ScanCreate, ScanOut, ScanSummary
)

router = APIRouter(tags=["Projects & Scans"])


# ---------- Projects ----------
@router.post("/projects", response_model=ProjectOut, status_code=201)
def create_project(
    project_in: ProjectCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = Project(
        name=project_in.name,
        target_base_url=project_in.target_base_url,
        description=project_in.description,
        is_authorized=project_in.is_authorized,
        authorization_note=project_in.authorization_note,
        owner_id=current_user.id,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@router.get("/projects", response_model=List[ProjectOut])
def list_projects(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return db.query(Project).filter(Project.owner_id == current_user.id).all()


# ---------- Scans ----------
@router.post("/scans", response_model=ScanOut, status_code=201)
async def create_scan(
    scan_in: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = db.query(Project).filter(
        Project.id == scan_in.project_id, Project.owner_id == current_user.id
    ).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not project.is_authorized:
        raise HTTPException(
            status_code=403,
            detail="This project is not marked as authorized for testing. "
                   "Confirm written authorization before scanning.",
        )

    scan = ScanRun(
        project_id=project.id,
        status=ScanStatus.PENDING,
        categories=",".join(scan_in.categories) if scan_in.categories else None,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Run the scan in the background so the API responds immediately
    background_tasks.add_task(
        _run_scan_background, scan.id, project.target_base_url, scan_in.categories
    )

    return scan


def _run_scan_background(scan_id: int, base_url: str, categories: list[str]):
    import asyncio
    from app.models.database import SessionLocal

    db = SessionLocal()
    try:
        asyncio.run(execute_scan(scan_id, base_url, categories, db))
    finally:
        db.close()


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = (
        db.query(ScanRun)
        .join(Project)
        .filter(ScanRun.id == scan_id, Project.owner_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/projects/{project_id}/scans", response_model=List[ScanSummary])
def list_scans_for_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = db.query(Project).filter(
        Project.id == project_id, Project.owner_id == current_user.id
    ).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    summaries = []
    for scan in project.scans:
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in scan.findings:
            if f.severity in sev_counts:
                sev_counts[f.severity] += 1
        summaries.append(ScanSummary(
            id=scan.id,
            project_id=scan.project_id,
            status=scan.status,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            total_findings=len(scan.findings),
            critical=sev_counts["Critical"],
            high=sev_counts["High"],
            medium=sev_counts["Medium"],
            low=sev_counts["Low"],
        ))
    return summaries
