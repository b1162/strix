"""SQLite persistence layer for cross-run vulnerability aggregation.

Database location: ``strix_runs/vulnerabilities.db``

Two tables:
- ``runs``            — one row per scan, updated on every save.
- ``vulnerabilities`` — one row per (vuln_id, run_id), upserted on every
  call to ``ReportState.add_vulnerability_report``.

JSON columns (``cvss_breakdown``, ``code_locations``, ``targets``) store
the raw dict/list as a JSON string so callers can parse them back without
a schema migration if the payload shape evolves.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

_lock = threading.Lock()

_DDL_RUNS = """
CREATE TABLE IF NOT EXISTS runs (
    run_id     TEXT PRIMARY KEY,
    run_name   TEXT,
    start_time TEXT,
    end_time   TEXT,
    status     TEXT,
    targets    TEXT
)
"""

_DDL_VULNS = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id                 TEXT    NOT NULL,
    run_id             TEXT    NOT NULL,
    title              TEXT    NOT NULL,
    severity           TEXT,
    timestamp          TEXT,
    description        TEXT,
    impact             TEXT,
    target             TEXT,
    technical_analysis TEXT,
    poc_description    TEXT,
    poc_script_code    TEXT,
    remediation_steps  TEXT,
    cvss               REAL,
    cvss_breakdown     TEXT,
    endpoint           TEXT,
    method             TEXT,
    cve                TEXT,
    cwe                TEXT,
    code_locations     TEXT,
    agent_id           TEXT,
    agent_name         TEXT,
    PRIMARY KEY (id, run_id),
    FOREIGN KEY (run_id) REFERENCES runs (run_id)
)
"""


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _ensure_tables(conn: sqlite3.Connection) -> None:
    conn.execute(_DDL_RUNS)
    conn.execute(_DDL_VULNS)


def init_db(db_path: Path) -> None:
    """Create tables if they do not exist yet. Safe to call multiple times."""
    with _lock, _connect(db_path) as conn:
        _ensure_tables(conn)


def upsert_run(
    db_path: Path,
    *,
    run_id: str,
    run_name: str | None,
    start_time: str | None,
    end_time: str | None,
    status: str,
    targets: list[Any] | None = None,
) -> None:
    """Insert or update a run row."""
    with _lock, _connect(db_path) as conn:
        _ensure_tables(conn)
        conn.execute(
            """
            INSERT INTO runs (run_id, run_name, start_time, end_time, status, targets)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id) DO UPDATE SET
                run_name   = excluded.run_name,
                start_time = excluded.start_time,
                end_time   = excluded.end_time,
                status     = excluded.status,
                targets    = excluded.targets
            """,
            (
                run_id,
                run_name,
                start_time,
                end_time,
                status,
                json.dumps(targets or []),
            ),
        )


def upsert_vulnerability(db_path: Path, run_id: str, vuln: dict[str, Any]) -> None:
    """Insert or update a single vulnerability row."""
    cvss_bd = vuln.get("cvss_breakdown")
    code_loc = vuln.get("code_locations")
    with _lock, _connect(db_path) as conn:
        _ensure_tables(conn)
        conn.execute(
            """
            INSERT INTO vulnerabilities (
                id, run_id, title, severity, timestamp, description, impact, target,
                technical_analysis, poc_description, poc_script_code, remediation_steps,
                cvss, cvss_breakdown, endpoint, method, cve, cwe,
                code_locations, agent_id, agent_name
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id, run_id) DO UPDATE SET
                title              = excluded.title,
                severity           = excluded.severity,
                timestamp          = excluded.timestamp,
                description        = excluded.description,
                impact             = excluded.impact,
                target             = excluded.target,
                technical_analysis = excluded.technical_analysis,
                poc_description    = excluded.poc_description,
                poc_script_code    = excluded.poc_script_code,
                remediation_steps  = excluded.remediation_steps,
                cvss               = excluded.cvss,
                cvss_breakdown     = excluded.cvss_breakdown,
                endpoint           = excluded.endpoint,
                method             = excluded.method,
                cve                = excluded.cve,
                cwe                = excluded.cwe,
                code_locations     = excluded.code_locations,
                agent_id           = excluded.agent_id,
                agent_name         = excluded.agent_name
            """,
            (
                vuln.get("id"),
                run_id,
                vuln.get("title", ""),
                vuln.get("severity"),
                vuln.get("timestamp"),
                vuln.get("description"),
                vuln.get("impact"),
                vuln.get("target"),
                vuln.get("technical_analysis"),
                vuln.get("poc_description"),
                vuln.get("poc_script_code"),
                vuln.get("remediation_steps"),
                vuln.get("cvss"),
                json.dumps(cvss_bd) if cvss_bd is not None else None,
                vuln.get("endpoint"),
                vuln.get("method"),
                vuln.get("cve"),
                vuln.get("cwe"),
                json.dumps(code_loc) if code_loc is not None else None,
                vuln.get("agent_id"),
                vuln.get("agent_name"),
            ),
        )
