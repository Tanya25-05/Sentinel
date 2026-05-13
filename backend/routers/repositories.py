"""
Repositories API router.
"""
from fastapi import APIRouter, HTTPException
from typing import List
from models import Repository
from database import fetch_all, fetch_one

router = APIRouter()

@router.post("/", response_model=Repository)
async def create_repository(url: str, branch: str = "main"):
    """Create a new repository entry."""
    import uuid
    repo_id = str(uuid.uuid4())
    repo = Repository(id=repo_id, url=url, branch=branch)
    await fetch_one("""
        INSERT INTO repositories (id, url, branch, created_at)
        VALUES ($1, $2, $3, $4)
    """, repo_id, url, branch, repo.created_at)
    return repo

@router.get("/", response_model=List[Repository])
async def list_repositories(limit: int = 50, offset: int = 0):
    """List all repositories."""
    repos = await fetch_all("SELECT * FROM repositories ORDER BY created_at DESC LIMIT $1 OFFSET $2", limit, offset)
    return [Repository(**r) for r in repos]

@router.get("/{repo_id}", response_model=Repository)
async def get_repository(repo_id: str):
    """Get repository details."""
    repo = await fetch_one("SELECT * FROM repositories WHERE id = $1", repo_id)
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    return Repository(**repo)