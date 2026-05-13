"""
Immutable audit log writer for SENTINEL.
All security-relevant actions are recorded with timestamp, actor IP, and details.
"""
from __future__ import annotations

import logging
from typing import Optional

import database

logger = logging.getLogger(__name__)


async def log(
    action: str,
    scan_id: Optional[str] = None,
    details: Optional[dict] = None,
    ip: str = "",
) -> None:
    """
    Write an immutable audit log entry.

    Actions:
      scan.created         — new scan queued
      scan.started         — scan execution begun
      scan.completed       — scan finished successfully
      scan.failed          — scan failed with error
      scan.deleted         — scan deleted by user
      vuln.viewed          — vulnerabilities listed for a scan
      ai.analysis.run      — AI analysis executed
      remediation.requested — remediation patch requested
      report.generated     — report downloaded
      health.check         — health endpoint hit
    """
    try:
        await database.write_audit_log(
            action=action,
            scan_id=scan_id,
            details=details or {},
            ip=ip,
        )
    except Exception as exc:
        logger.error("Audit log write failed for action=%s: %s", action, exc)


# Convenience wrappers
async def scan_created(scan_id: str, repo_url: str, profile: str, ip: str = "") -> None:
    await log("scan.created", scan_id, {"repo_url": repo_url, "profile": profile}, ip)


async def scan_started(scan_id: str) -> None:
    await log("scan.started", scan_id, {})


async def scan_completed(scan_id: str, vuln_count: int, risk_score: float) -> None:
    await log("scan.completed", scan_id, {"vuln_count": vuln_count, "risk_score": risk_score})


async def scan_failed(scan_id: str, error: str) -> None:
    await log("scan.failed", scan_id, {"error": error})


async def scan_deleted(scan_id: str, ip: str = "") -> None:
    await log("scan.deleted", scan_id, {}, ip)


async def ai_analysis_run(scan_id: str, risk_score: float, vuln_count: int) -> None:
    await log("ai.analysis.run", scan_id, {"risk_score": risk_score, "vuln_count": vuln_count})


async def remediation_requested(scan_id: str, vuln_id: str, ip: str = "") -> None:
    await log("remediation.requested", scan_id, {"vuln_id": vuln_id}, ip)


async def report_generated(scan_id: str, fmt: str, ip: str = "") -> None:
    await log("report.generated", scan_id, {"format": fmt}, ip)
