"""
API routers for SENTINEL backend.
"""
from fastapi import APIRouter

from .scans import router as scans_router
from .repositories import router as repos_router
from .reports import router as reports_router

router = APIRouter()
router.include_router(scans_router, prefix="/scans", tags=["scans"])
router.include_router(repos_router, prefix="/repositories", tags=["repositories"])
router.include_router(reports_router, prefix="/reports", tags=["reports"])