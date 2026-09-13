from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.models.database import get_db
from app.models.models import ScanRun, Project, User
from app.routers.deps import get_current_user
from app.reports.report_generator import render_html_report, render_pdf_report

router = APIRouter(prefix="/reports", tags=["Reports"])


def _get_scan_and_project(scan_id: int, db: Session, current_user: User):
    scan = (
        db.query(ScanRun)
        .join(Project)
        .filter(ScanRun.id == scan_id, Project.owner_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    project = db.query(Project).filter(Project.id == scan.project_id).first()
    return scan, project


@router.get("/{scan_id}/html")
def get_html_report(
    scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    scan, project = _get_scan_and_project(scan_id, db, current_user)
    path = render_html_report(scan, project)
    return FileResponse(path, media_type="text/html", filename=f"scan_{scan_id}_report.html")


@router.get("/{scan_id}/pdf")
def get_pdf_report(
    scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
):
    scan, project = _get_scan_and_project(scan_id, db, current_user)
    try:
        path = render_pdf_report(scan, project)
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="PDF generation requires the 'weasyprint' package and its system "
                   "dependencies to be installed on the server.",
        )
    return FileResponse(path, media_type="application/pdf", filename=f"scan_{scan_id}_report.pdf")
