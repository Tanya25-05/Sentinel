"""
Reports API router.
"""
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from typing import List
from models import Report
from database import fetch_all, fetch_one
from services.report_generator import generate_report

router = APIRouter()

@router.post("/{scan_id}", response_model=Report)
async def create_report(scan_id: str, format: str = "pdf"):
    """Generate a report for a scan."""
    # Check if scan exists
    scan = await fetch_one("SELECT * FROM scans WHERE id = $1", scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Generate report
    report_content = await generate_report(scan_id, format)

    import uuid
    report_id = str(uuid.uuid4())
    report = Report(id=report_id, scan_id=scan_id, format=format, content=report_content)

    await fetch_one("""
        INSERT INTO reports (id, scan_id, format, content, created_at)
        VALUES ($1, $2, $3, $4, $5)
    """, report_id, scan_id, format, report_content, report.created_at)

    return report

@router.get("/{report_id}/download")
async def download_report(report_id: str):
    """Download a report."""
    report = await fetch_one("SELECT * FROM reports WHERE id = $1", report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return StreamingResponse(
        iter([report["content"]]),
        media_type="application/pdf" if report["format"] == "pdf" else "application/json",
        headers={"Content-Disposition": f"attachment; filename=report.{report['format']}"}
    )

@router.get("/", response_model=List[Report])
async def list_reports(scan_id: str = None, limit: int = 50, offset: int = 0):
    """List reports, optionally filtered by scan."""
    if scan_id:
        reports = await fetch_all("SELECT * FROM reports WHERE scan_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3", scan_id, limit, offset)
    else:
        reports = await fetch_all("SELECT * FROM reports ORDER BY created_at DESC LIMIT $1 OFFSET $2", limit, offset)
    return [Report(**r) for r in reports]