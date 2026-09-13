"""
Orchestrates execution of all scanner modules against an authorized target,
persists findings, and updates the ScanRun status.
"""
import asyncio
from datetime import datetime

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.models import ScanRun, ScanStatus, Finding
from app.scanners import (
    auth_session,
    access_control,
    input_validation,
    api_security,
    client_side,
    transport_security,
    data_storage,
)

SCANNER_REGISTRY = {
    "auth_session": auth_session,
    "access_control": access_control,
    "input_validation": input_validation,
    "api_security": api_security,
    "client_side": client_side,
    "transport_security": transport_security,
    "data_storage": data_storage,
}


async def execute_scan(scan_id: int, base_url: str, categories: list[str], db: Session):
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        return

    scan.status = ScanStatus.RUNNING
    db.commit()

    modules_to_run = (
        [SCANNER_REGISTRY[c] for c in categories if c in SCANNER_REGISTRY]
        if categories else list(SCANNER_REGISTRY.values())
    )

    try:
        async with httpx.AsyncClient(
            timeout=settings.REQUEST_TIMEOUT_SECONDS,
            verify=True,
            headers={"User-Agent": "SecurityAssessmentPlatform/1.0 (authorized-scan)"},
        ) as client:
            results = await asyncio.gather(
                *(module.run(base_url, client) for module in modules_to_run),
                return_exceptions=True,
            )

        for module, result in zip(modules_to_run, results):
            if isinstance(result, Exception):
                continue  # one failing scanner should not fail the whole run
            for finding_dict in result:
                db.add(Finding(scan_id=scan.id, **finding_dict))

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        db.commit()

    except Exception as e:
        scan.status = ScanStatus.FAILED
        scan.error_message = str(e)
        scan.completed_at = datetime.utcnow()
        db.commit()
