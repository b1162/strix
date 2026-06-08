"""Run directory path helpers."""

from __future__ import annotations

from pathlib import Path


RUNS_DIR_NAME = "strix_runs"
RUNTIME_STATE_DIR_NAME = ".state"
RUN_RECORD_FILENAME = "run.json"
VULNS_DB_FILENAME = "vulnerabilities.db"


def run_dir_for(run_name: str, *, cwd: Path | None = None) -> Path:
    base = cwd or Path.cwd()
    return base / RUNS_DIR_NAME / run_name


def runtime_state_dir(run_dir: Path) -> Path:
    return run_dir / RUNTIME_STATE_DIR_NAME


def run_record_path(run_dir: Path) -> Path:
    return run_dir / RUN_RECORD_FILENAME


def vulns_db_path(run_dir: Path) -> Path:
    """Global vulnerability DB shared across all runs: ``strix_runs/vulnerabilities.db``."""
    return run_dir.parent / VULNS_DB_FILENAME
