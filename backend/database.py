"""
Database layer for SENTINEL.
- If DATABASE_URL is set → asyncpg pool against PostgreSQL
- If not set → in-memory dict storage fallback (no persistence)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory fallback storage
# ---------------------------------------------------------------------------

_mem: dict[str, dict] = {
    "scans": {},
    "vulnerabilities": {},
    "ai_analyses": {},
    "audit_logs": {},
}


class _MemRow(dict):
    """Dict that also supports attribute-style access like asyncpg Record."""
    def __getattr__(self, item):
        try:
            return self[item]
        except KeyError:
            raise AttributeError(item)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Database wrapper interface
# ---------------------------------------------------------------------------

_pool = None  # asyncpg pool, None if using in-memory


async def init_db() -> None:
    """Create tables (asyncpg) or seed in-memory store."""
    global _pool
    db_url = os.getenv("DATABASE_URL", "")
    if not db_url:
        logger.warning("DATABASE_URL not set — using in-memory storage (no persistence)")
        _seed_memory()
        return

    try:
        import asyncpg
        from models import DB_SCHEMA_SQL

        _pool = await asyncpg.create_pool(db_url, min_size=2, max_size=10, command_timeout=30)

        async with _pool.acquire() as conn:
            for stmt in DB_SCHEMA_SQL:
                await conn.execute(stmt)

        logger.info("PostgreSQL connected and tables created")
    except Exception as exc:
        logger.error("Failed to connect to PostgreSQL: %s — falling back to in-memory", exc)
        _pool = None
        _seed_memory()


async def close_db() -> None:
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


def using_postgres() -> bool:
    return _pool is not None


# ---------------------------------------------------------------------------
# Unified query interface
# ---------------------------------------------------------------------------

async def fetch_all(query: str, *args) -> list[dict]:
    if _pool:
        async with _pool.acquire() as conn:
            rows = await conn.fetch(query, *args)
            return [dict(r) for r in rows]
    raise RuntimeError("fetch_all called but no pg pool — use mem helpers")


async def fetch_one(query: str, *args) -> Optional[dict]:
    if _pool:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(query, *args)
            return dict(row) if row else None
    raise RuntimeError("fetch_one called but no pg pool")


async def execute(query: str, *args) -> str:
    if _pool:
        async with _pool.acquire() as conn:
            return await conn.execute(query, *args)
    raise RuntimeError("execute called but no pg pool")


async def execute_many(query: str, args_list: list) -> None:
    if _pool:
        async with _pool.acquire() as conn:
            await conn.executemany(query, args_list)


# ---------------------------------------------------------------------------
# High-level DB helpers (work for both backends)
# ---------------------------------------------------------------------------

async def create_scan(repo_url: str, branch: str, scan_profile: str, queue_position: int) -> dict:
    scan_id = str(uuid.uuid4())
    if using_postgres():
        row = await fetch_one(
            """
            INSERT INTO scans (id, repo_url, branch, scan_profile, status, progress, queue_position)
            VALUES ($1::uuid, $2, $3, $4, 'queued', 0, $5)
            RETURNING *
            """,
            scan_id, repo_url, branch, scan_profile, queue_position,
        )
        return row
    else:
        row = _MemRow({
            "id": scan_id,
            "repo_url": repo_url,
            "branch": branch,
            "scan_profile": scan_profile,
            "status": "queued",
            "progress": 0,
            "queue_position": queue_position,
            "started_at": None,
            "completed_at": None,
            "container_id": None,
            "modules_run": [],
            "created_at": _now(),
        })
        _mem["scans"][scan_id] = row
        return row


async def get_scan(scan_id: str) -> Optional[dict]:
    if using_postgres():
        return await fetch_one("SELECT * FROM scans WHERE id = $1::uuid", scan_id)
    return _mem["scans"].get(scan_id)


async def list_scans(limit: int = 100) -> list[dict]:
    if using_postgres():
        return await fetch_all("SELECT * FROM scans ORDER BY created_at DESC LIMIT $1", limit)
    rows = sorted(_mem["scans"].values(), key=lambda r: r.get("created_at", _now()), reverse=True)
    return list(rows)[:limit]


async def update_scan(scan_id: str, **fields) -> Optional[dict]:
    if using_postgres():
        # Build SET clause dynamically
        col_map = {
            "status": "status",
            "progress": "progress",
            "queue_position": "queue_position",
            "started_at": "started_at",
            "completed_at": "completed_at",
            "container_id": "container_id",
            "modules_run": "modules_run",
        }
        set_parts = []
        vals = []
        idx = 1
        for k, v in fields.items():
            if k in col_map:
                if k == "modules_run" and isinstance(v, (list, dict)):
                    v = json.dumps(v)
                set_parts.append(f"{col_map[k]} = ${idx}")
                vals.append(v)
                idx += 1
        if not set_parts:
            return await get_scan(scan_id)
        vals.append(scan_id)
        query = f"UPDATE scans SET {', '.join(set_parts)} WHERE id = ${idx}::uuid RETURNING *"
        return await fetch_one(query, *vals)
    else:
        row = _mem["scans"].get(scan_id)
        if not row:
            return None
        for k, v in fields.items():
            row[k] = v
        return row


async def delete_scan(scan_id: str) -> bool:
    if using_postgres():
        result = await execute("DELETE FROM scans WHERE id = $1::uuid", scan_id)
        return result == "DELETE 1"
    if scan_id in _mem["scans"]:
        del _mem["scans"][scan_id]
        # cascade vulns
        _mem["vulnerabilities"] = {
            k: v for k, v in _mem["vulnerabilities"].items()
            if str(v.get("scan_id")) != scan_id
        }
        _mem["ai_analyses"] = {
            k: v for k, v in _mem["ai_analyses"].items()
            if str(v.get("scan_id")) != scan_id
        }
        return True
    return False


async def insert_vulnerability(vuln: dict) -> dict:
    vid = str(uuid.uuid4())
    if using_postgres():
        row = await fetch_one(
            """
            INSERT INTO vulnerabilities
              (id, scan_id, severity, category, title, file, line_start, line_end,
               description, snippet, cvss, cwe, owasp, remediation, ai_confidence,
               false_positive, tool)
            VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
            RETURNING *
            """,
            vid,
            vuln["scan_id"], vuln["severity"], vuln["category"], vuln["title"],
            vuln["file"], vuln["line_start"], vuln["line_end"], vuln["description"],
            vuln["snippet"], vuln["cvss"], vuln["cwe"], vuln["owasp"],
            vuln["remediation"], vuln["ai_confidence"], vuln.get("false_positive", False),
            vuln["tool"],
        )
        return row
    else:
        row = _MemRow({**vuln, "id": vid, "created_at": _now()})
        _mem["vulnerabilities"][vid] = row
        return row


async def get_vulnerabilities(scan_id: str, severity: Optional[str] = None,
                               category: Optional[str] = None,
                               page: int = 1, page_size: int = 50) -> tuple[list[dict], int]:
    if using_postgres():
        conditions = ["scan_id = $1::uuid"]
        vals: list[Any] = [scan_id]
        idx = 2
        if severity:
            conditions.append(f"severity = ${idx}")
            vals.append(severity)
            idx += 1
        if category:
            conditions.append(f"category = ${idx}")
            vals.append(category)
            idx += 1
        where = " AND ".join(conditions)
        total_row = await fetch_one(f"SELECT COUNT(*) as cnt FROM vulnerabilities WHERE {where}", *vals)
        total = int(total_row["cnt"]) if total_row else 0
        offset = (page - 1) * page_size
        rows = await fetch_all(
            f"SELECT * FROM vulnerabilities WHERE {where} ORDER BY cvss DESC LIMIT ${idx} OFFSET ${idx+1}",
            *vals, page_size, offset,
        )
        return rows, total
    else:
        rows = [v for v in _mem["vulnerabilities"].values() if str(v.get("scan_id")) == scan_id]
        if severity:
            rows = [v for v in rows if v.get("severity") == severity]
        if category:
            rows = [v for v in rows if v.get("category") == category]
        total = len(rows)
        rows.sort(key=lambda v: float(v.get("cvss", 0)), reverse=True)
        offset = (page - 1) * page_size
        return rows[offset: offset + page_size], total


async def get_vuln_counts(scan_id: str) -> dict[str, int]:
    if using_postgres():
        rows = await fetch_all(
            "SELECT severity, COUNT(*) as cnt FROM vulnerabilities WHERE scan_id = $1::uuid GROUP BY severity",
            scan_id,
        )
        return {r["severity"]: int(r["cnt"]) for r in rows}
    else:
        rows = [v for v in _mem["vulnerabilities"].values() if str(v.get("scan_id")) == scan_id]
        result: dict[str, int] = {}
        for r in rows:
            s = r.get("severity", "info")
            result[s] = result.get(s, 0) + 1
        return result


async def upsert_ai_analysis(scan_id: str, data: dict) -> dict:
    aid = str(uuid.uuid4())
    if using_postgres():
        # Delete existing first
        await execute("DELETE FROM ai_analyses WHERE scan_id = $1::uuid", scan_id)
        row = await fetch_one(
            """
            INSERT INTO ai_analyses (id, scan_id, risk_score, attack_chains, prioritized, remediations, threat_model)
            VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7)
            RETURNING *
            """,
            aid, scan_id,
            data["risk_score"],
            json.dumps(data["attack_chains"]),
            json.dumps(data["prioritized"]),
            json.dumps(data["remediations"]),
            data["threat_model"],
        )
        return row
    else:
        # Remove old
        _mem["ai_analyses"] = {k: v for k, v in _mem["ai_analyses"].items()
                                if str(v.get("scan_id")) != scan_id}
        row = _MemRow({**data, "id": aid, "scan_id": scan_id, "generated_at": _now()})
        _mem["ai_analyses"][aid] = row
        return row


async def get_ai_analysis(scan_id: str) -> Optional[dict]:
    if using_postgres():
        return await fetch_one("SELECT * FROM ai_analyses WHERE scan_id = $1::uuid ORDER BY generated_at DESC LIMIT 1", scan_id)
    for v in _mem["ai_analyses"].values():
        if str(v.get("scan_id")) == scan_id:
            return v
    return None


async def write_audit_log(action: str, scan_id: Optional[str], details: dict, ip: str = "") -> None:
    try:
        if using_postgres():
            sid = scan_id if scan_id else None
            await execute(
                "INSERT INTO audit_logs (action, scan_id, details, ip_address) VALUES ($1, $2::uuid, $3, $4)",
                action, sid, json.dumps(details), ip,
            )
        else:
            lid = str(uuid.uuid4())
            _mem["audit_logs"][lid] = _MemRow({
                "id": lid,
                "action": action,
                "scan_id": scan_id,
                "details": details,
                "ip_address": ip,
                "timestamp": _now(),
            })
    except Exception as exc:
        logger.error("audit_log write failed: %s", exc)


# ---------------------------------------------------------------------------
# Dashboard aggregates
# ---------------------------------------------------------------------------

async def get_dashboard_data() -> dict:
    if using_postgres():
        scans = await fetch_all("SELECT * FROM scans ORDER BY created_at DESC")
        vuln_rows = await fetch_all(
            "SELECT severity, COUNT(*) as cnt FROM vulnerabilities GROUP BY severity"
        )
        category_rows = await fetch_all(
            "SELECT category, COUNT(*) as cnt FROM vulnerabilities GROUP BY category ORDER BY cnt DESC LIMIT 10"
        )
        trend_rows = await fetch_all(
            """
            SELECT DATE(created_at) as date, COUNT(*) as cnt
            FROM scans
            WHERE created_at > NOW() - INTERVAL '30 days'
            GROUP BY DATE(created_at)
            ORDER BY date
            """
        )
        # avg scan time
        avg_row = await fetch_one(
            """
            SELECT AVG(EXTRACT(EPOCH FROM (completed_at - started_at))) as avg_sec
            FROM scans WHERE status='completed' AND started_at IS NOT NULL AND completed_at IS NOT NULL
            """
        )
        return {
            "scans": scans,
            "vuln_rows": vuln_rows,
            "category_rows": category_rows,
            "trend_rows": trend_rows,
            "avg_sec": float(avg_row["avg_sec"] or 0) if avg_row else 0,
        }
    else:
        scans = list(_mem["scans"].values())
        vulns = list(_mem["vulnerabilities"].values())
        vuln_by_sev: dict[str, int] = {}
        cat_count: dict[str, int] = {}
        for v in vulns:
            s = v.get("severity", "info")
            vuln_by_sev[s] = vuln_by_sev.get(s, 0) + 1
            c = v.get("category", "Unknown")
            cat_count[c] = cat_count.get(c, 0) + 1
        vuln_rows = [{"severity": k, "cnt": v} for k, v in vuln_by_sev.items()]
        category_rows = sorted([{"category": k, "cnt": v} for k, v in cat_count.items()],
                                key=lambda x: x["cnt"], reverse=True)[:10]
        # trend last 30 days
        from collections import defaultdict
        trend: dict[str, int] = defaultdict(int)
        for s in scans:
            created = s.get("created_at")
            if created:
                if isinstance(created, datetime):
                    date_str = created.strftime("%Y-%m-%d")
                else:
                    date_str = str(created)[:10]
                trend[date_str] += 1
        trend_rows = [{"date": k, "cnt": v} for k, v in sorted(trend.items())]
        # avg scan time
        times = []
        for s in scans:
            if s.get("started_at") and s.get("completed_at"):
                sa, ca = s["started_at"], s["completed_at"]
                if isinstance(sa, datetime) and isinstance(ca, datetime):
                    times.append((ca - sa).total_seconds())
        avg_sec = sum(times) / len(times) if times else 0
        return {
            "scans": scans,
            "vuln_rows": vuln_rows,
            "category_rows": category_rows,
            "trend_rows": trend_rows,
            "avg_sec": avg_sec,
        }


# ---------------------------------------------------------------------------
# Seed data for in-memory demo
# ---------------------------------------------------------------------------

def _seed_memory() -> None:
    """Populate in-memory store with realistic demo data."""
    import random
    from datetime import timedelta

    now = _now()
    profiles = ["quick", "standard", "deep"]
    statuses = ["completed", "completed", "completed", "failed", "running"]
    repos = [
        "https://github.com/example/web-app",
        "https://github.com/acme/api-service",
        "https://github.com/corp/backend-core",
        "https://github.com/startup/mobile-api",
        "https://github.com/enterprise/auth-service",
    ]

    for i, repo in enumerate(repos):
        scan_id = str(uuid.uuid4())
        created = now - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23))
        status = statuses[i % len(statuses)]
        profile = profiles[i % len(profiles)]
        started = created + timedelta(minutes=1) if status != "queued" else None
        completed = (started + timedelta(minutes=random.randint(2, 45))
                     if status in ("completed", "failed") and started else None)

        modules = _build_modules(profile, status)

        _mem["scans"][scan_id] = _MemRow({
            "id": scan_id,
            "repo_url": repo,
            "branch": "main",
            "scan_profile": profile,
            "status": status,
            "progress": 100 if status == "completed" else (0 if status == "queued" else 65),
            "queue_position": None,
            "started_at": started,
            "completed_at": completed,
            "container_id": f"sentinel_{scan_id[:8]}" if started else None,
            "modules_run": modules,
            "created_at": created,
        })

        if status == "completed":
            from services.scanner_runner import generate_mock_vulnerabilities
            vulns = generate_mock_vulnerabilities(scan_id, profile)
            for v in vulns:
                vid = str(uuid.uuid4())
                row = _MemRow({**v, "id": vid, "created_at": _now()})
                _mem["vulnerabilities"][vid] = row

            # ai analysis seed
            ai_id = str(uuid.uuid4())
            _mem["ai_analyses"][ai_id] = _MemRow({
                "id": ai_id,
                "scan_id": scan_id,
                "risk_score": round(random.uniform(4.5, 9.2), 1),
                "attack_chains": [],
                "prioritized": [],
                "remediations": [],
                "threat_model": "Seed threat model — run a fresh scan for full AI analysis.",
                "generated_at": now,
            })


def _build_modules(profile: str, status: str) -> list[dict]:
    module_map = {
        "quick": ["semgrep_sast", "dependency_check"],
        "standard": ["semgrep_sast", "dependency_check", "secret_scan", "docker_scan"],
        "deep": ["semgrep_sast", "dependency_check", "secret_scan", "docker_scan", "ai_logic_analysis", "api_scan"],
    }
    names = module_map.get(profile, module_map["standard"])
    mods = []
    for name in names:
        if status == "completed":
            import random
            mods.append({"name": name, "status": "completed", "vulnsFound": random.randint(0, 12)})
        elif status == "running":
            mods.append({"name": name, "status": "pending", "vulnsFound": 0})
        else:
            mods.append({"name": name, "status": "skipped", "vulnsFound": 0})
    return mods
