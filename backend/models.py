"""
Database models and schema for SENTINEL security platform.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import BaseModel, Field
from enum import Enum

# ------------------------------------------------------------------------------
# Enums
# ------------------------------------------------------------------------------

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class VulnerabilityCategory(str, Enum):
    SQL_INJECTION = "SQL Injection"
    XSS = "XSS"
    RCE = "RCE"
    SSRF = "SSRF"
    AUTH_BYPASS = "Authentication Bypass"
    DEPENDENCY_EXPLOIT = "Dependency Exploit"
    BUSINESS_LOGIC = "Business Logic Flaw"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    SUPPLY_CHAIN = "Supply Chain Attack"
    PROMPT_INJECTION = "Prompt Injection"
    MCP_TOOL_MISUSE = "MCP/Tool Misuse"
    UNSAFE_API = "Unsafe API Usage"

# ------------------------------------------------------------------------------
# Pydantic Models
# ------------------------------------------------------------------------------

class Repository(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    url: str
    branch: str = "main"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_scanned: Optional[datetime] = None

class Scan(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repo_url: str
    branch: str = "main"
    status: ScanStatus = ScanStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    findings_count: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Vulnerability(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    file_path: str
    line_number: Optional[int] = None
    category: VulnerabilityCategory
    severity: Severity
    description: str
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_top_10: Optional[str] = None
    remediation: Optional[str] = None
    ai_analysis: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AttackChain(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    title: str
    steps: list[str]
    severity: Severity
    likelihood: str  # high, medium, low
    impact: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AuditLog(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: Optional[str] = None
    action: str
    resource: str
    details: dict[str, Any] = {}
    ip_address: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Report(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    format: str  # pdf, json, html
    content: bytes
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# ------------------------------------------------------------------------------
# Database Schema SQL
# ------------------------------------------------------------------------------

DB_SCHEMA_SQL = [
    """
    CREATE TABLE IF NOT EXISTS repositories (
        id TEXT PRIMARY KEY,
        url TEXT NOT NULL,
        branch TEXT NOT NULL DEFAULT 'main',
        created_at TIMESTAMP WITH TIME ZONE NOT NULL,
        last_scanned TIMESTAMP WITH TIME ZONE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        repo_url TEXT NOT NULL,
        branch TEXT NOT NULL DEFAULT 'main',
        status TEXT NOT NULL DEFAULT 'pending',
        started_at TIMESTAMP WITH TIME ZONE,
        completed_at TIMESTAMP WITH TIME ZONE,
        findings_count INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        file_path TEXT NOT NULL,
        line_number INTEGER,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        description TEXT NOT NULL,
        code_snippet TEXT,
        cwe_id TEXT,
        owasp_top_10 TEXT,
        remediation TEXT,
        ai_analysis TEXT,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS attack_chains (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        steps JSONB NOT NULL,
        severity TEXT NOT NULL,
        likelihood TEXT NOT NULL,
        impact TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        action TEXT NOT NULL,
        resource TEXT NOT NULL,
        details JSONB NOT NULL DEFAULT '{}',
        ip_address TEXT,
        timestamp TIMESTAMP WITH TIME ZONE NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS reports (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        format TEXT NOT NULL,
        content BYTEA NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL
    );
    """,
    # Indexes for performance
    "CREATE INDEX IF NOT EXISTS idx_scans_repo_id ON scans(repo_id);",
    "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);",
    "CREATE INDEX IF NOT EXISTS idx_attack_chains_scan_id ON attack_chains(scan_id);",
    "CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports(scan_id);",
]