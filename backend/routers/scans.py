"""
Scans API router.
"""
import uuid
from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List
from models import Scan, ScanStatus
from services.scanner_runner import run_scan_async
from database import fetch_all, fetch_one

router = APIRouter()

@router.post("/", response_model=Scan)
async def create_scan(repo_url: str, branch: str = "main", background_tasks: BackgroundTasks = None):
    """Create a new security scan for a repository."""
    # Check if repo exists or create it
    repo = await fetch_one("SELECT * FROM repositories WHERE url = $1 AND branch = $2", repo_url, branch)
    if not repo:
        # Create repo
        repo_id = str(uuid.uuid4())
        await fetch_one("INSERT INTO repositories (id, url, branch) VALUES ($1, $2, $3)", repo_id, repo_url, branch)
    else:
        repo_id = repo["id"]

    # Create scan
    scan_id = str(uuid.uuid4())
    scan = Scan(id=scan_id, repo_id=repo_id, status=ScanStatus.PENDING)
    await fetch_one("""
        INSERT INTO scans (id, repo_id, status, created_at)
        VALUES ($1, $2, $3, $4)
    """, scan_id, repo_id, scan.status.value, scan.created_at)

    # Start scan in background
    if background_tasks:
        background_tasks.add_task(run_scan_async, scan_id)

    return scan

@router.get("/{scan_id}", response_model=Scan)
async def get_scan(scan_id: str):
    """Get scan details."""
    scan = await fetch_one("SELECT * FROM scans WHERE id = $1", scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return Scan(**scan)

@router.get("/", response_model=List[Scan])
async def list_scans(limit: int = 50, offset: int = 0):
    """List all scans."""
    scans = await fetch_all("SELECT * FROM scans ORDER BY created_at DESC LIMIT $1 OFFSET $2", limit, offset)
    return [Scan(**s) for s in scans]