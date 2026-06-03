"""``run_sqlmap`` — run non-interactive sqlmap scan inside the sandbox."""

from __future__ import annotations

import json
import logging

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


@function_tool(timeout=605)
async def run_sqlmap(
    ctx: RunContextWrapper,
    url: str,
    parameter: str | None = None,
    data: str | None = None,
    cookie: str | None = None,
    headers: list[str] | None = None,
    level: int = 1,
    risk: int = 1,
    techniques: str | None = None,
    flush_session: bool = False,
    timeout_seconds: int = 600,
) -> str:
    """Run non-interactive sqlmap scan against a URL parameter.

    This tool wraps sqlmap for secure, fast, and automated SQL injection testing and verification.
    It executes inside the sandbox environment, leveraging caido proxying automatically.

    Speed Optimization:
    - Avoids interactive prompts (`--batch`).
    - Leverages concurrency (`--threads 5`).
    - Uses conservative defaults (level 1, risk 1, techniques EBU: Error, Boolean, Union).
      Time-based and stacked queries can be slow; restrict to fast techniques unless required.

    Args:
        url: Target URL to test (e.g. "http://target/item.php?id=1").
        parameter: Specific parameter(s) to test (e.g. "id"). Highly recommended to focus sqlmap.
        data: HTTP POST data string (e.g. "user=admin&pass=123"). If provided, sqlmap runs POST test.
        cookie: HTTP Cookie header value (e.g. "PHPSESSID=abc").
        headers: List of custom headers (e.g. ["Authorization: Bearer xyz"]).
        level: Level of tests to perform (1-5, default 1).
        risk: Risk of tests to perform (1-3, default 1).
        techniques: Techniques to test (default "EBU" for Error, Boolean, Union).
        flush_session: Flush session files (clear cached scan state).
        timeout_seconds: Maximum time in seconds to wait for sqlmap execution (default 600).
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    session = inner.get("sandbox_session")
    if session is None:
        return json.dumps(
            {"success": False, "error": "Sandbox session not available in run context"},
            ensure_ascii=False,
            default=str,
        )

    # Build sqlmap command arguments
    args = [
        "-u",
        url,
        "--batch",
        "--threads",
        "5",
        "--timeout",
        "10",
        "--retries",
        "1",
    ]

    if parameter:
        args.extend(["-p", parameter])
    if data:
        args.extend(["--data", data])
    if cookie:
        args.extend(["--cookie", cookie])
    if headers:
        for h in headers:
            args.extend(["--header", h])

    # Default to EBU (Error, Boolean, Union) for speed, unless specified otherwise
    tech = techniques if techniques is not None else "EBU"
    if tech:
        args.extend(["--technique", tech])

    args.extend(["--level", str(level)])
    args.extend(["--risk", str(risk)])

    if flush_session:
        args.append("--flush-session")

    logger.info("run_sqlmap: invoking inside sandbox: sqlmap %s", " ".join(args))

    try:
        result = await session.exec("sqlmap", *args, timeout=float(timeout_seconds))
    except Exception as exc:
        logger.exception("run_sqlmap: failed to execute sqlmap")
        return json.dumps(
            {"success": False, "error": f"Failed to execute sqlmap: {exc}"},
            ensure_ascii=False,
            default=str,
        )

    # Process results safely
    stdout_bytes = getattr(result, "stdout", b"")
    stdout = (
        stdout_bytes.decode("utf-8", errors="replace")
        if isinstance(stdout_bytes, bytes)
        else str(stdout_bytes)
    )
    stderr_bytes = getattr(result, "stderr", b"")
    stderr = (
        stderr_bytes.decode("utf-8", errors="replace")
        if isinstance(stderr_bytes, bytes)
        else str(stderr_bytes)
    )
    exit_code = getattr(result, "exit_code", -1)

    # Filter/clean stdout to extract high-signal info and prevent token bloat
    lines = stdout.splitlines()
    high_signal_lines = []
    summary_lines = []
    in_summary = False

    for line in lines:
        if (
            "identified the following injection point" in line
            or "sqlmap identified the following" in line
        ):
            in_summary = True

        if in_summary:
            summary_lines.append(line)
        elif (
            "[INFO] the back-end DBMS is" in line
            or "[INFO] target URL is vulnerable" in line
            or "[ERROR]" in line
            or "[CRITICAL]" in line
        ):
            high_signal_lines.append(line)

    clean_output = "\n".join(high_signal_lines)
    if summary_lines:
        clean_output += "\n\n=== Injection Summary ===\n" + "\n".join(summary_lines)

    # If the output is completely empty, fallback to the last 50 lines of stdout
    if not clean_output.strip():
        clean_output = "\n".join(lines[-50:])

    is_vulnerable = "vulnerable" in stdout.lower() or in_summary

    return json.dumps(
        {
            "success": result.ok() if hasattr(result, "ok") else (exit_code == 0),
            "exit_code": exit_code,
            "vulnerable": is_vulnerable,
            "stdout_summary": clean_output,
            "stderr": stderr if exit_code != 0 else "",
        },
        ensure_ascii=False,
        default=str,
    )
