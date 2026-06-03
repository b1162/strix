#!/usr/bin/env python3
"""
Strix Agent Interface
"""

import argparse
import asyncio
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from agents.models.multi_provider import MultiProvider
from docker.errors import DockerException
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.config import (
    apply_config_override,
    load_settings,
    persist_current,
)
from strix.config.models import configure_sdk_model_defaults, normalize_model_name
from strix.core.paths import RUN_RECORD_FILENAME, RUNS_DIR_NAME, run_dir_for, runtime_state_dir
from strix.interface.cli import run_cli
from strix.interface.tui import run_tui
from strix.interface.utils import (
    assign_workspace_subdirs,
    build_final_stats_text,
    check_docker_connection,
    clone_repository,
    collect_local_sources,
    generate_run_name,
    image_exists,
    infer_target_type,
    is_whitebox_scan,
    process_pull_line,
    resolve_diff_scope_context,
    rewrite_localhost_targets,
    validate_config_file,
)
from strix.report.state import get_global_report_state
from strix.report.writer import read_run_record, write_run_record
from strix.telemetry import posthog, scarf
from strix.telemetry.logging import configure_dependency_logging


HOST_GATEWAY_HOSTNAME = "host.docker.internal"


import logging  # noqa: E402


logger = logging.getLogger(__name__)


def validate_environment() -> None:
    logger.info("Validating environment")
    console = Console()
    missing_required_vars = []
    missing_optional_vars = []

    settings = load_settings()

    if not settings.llm.model:
        missing_required_vars.append("STRIX_LLM")

    if not settings.llm.api_key:
        missing_optional_vars.append("LLM_API_KEY")

    if not settings.llm.api_base:
        missing_optional_vars.append("LLM_API_BASE")

    if not settings.integrations.perplexity_api_key:
        missing_optional_vars.append("PERPLEXITY_API_KEY")

    if missing_required_vars:
        error_text = Text()
        error_text.append("MISSING REQUIRED ENVIRONMENT VARIABLES", style="bold red")
        error_text.append("\n\n", style="white")

        for var in missing_required_vars:
            error_text.append(f"• {var}", style="bold yellow")
            error_text.append(" is not set\n", style="white")

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="dim white")
            for var in missing_optional_vars:
                error_text.append(f"• {var}", style="dim yellow")
                error_text.append(" is not set\n", style="dim white")

        error_text.append("\nRequired environment variables:\n", style="white")
        for var in missing_required_vars:
            if var == "STRIX_LLM":
                error_text.append("• ", style="white")
                error_text.append("STRIX_LLM", style="bold cyan")
                error_text.append(
                    " - Model name to use (e.g., 'gpt-5.4' or 'claude-sonnet-4-6')\n",
                    style="white",
                )

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="white")
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_KEY", style="bold cyan")
                    error_text.append(
                        " - API key for the LLM provider "
                        "(not needed for local models, Vertex AI, AWS, etc.)\n",
                        style="white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_BASE", style="bold cyan")
                    error_text.append(
                        " - Custom API base URL if using local models (e.g., Ollama, LMStudio)\n",
                        style="white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("PERPLEXITY_API_KEY", style="bold cyan")
                    error_text.append(
                        " - API key for Perplexity AI web search (enables real-time research)\n",
                        style="white",
                    )
                elif var == "STRIX_REASONING_EFFORT":
                    error_text.append("• ", style="white")
                    error_text.append("STRIX_REASONING_EFFORT", style="bold cyan")
                    error_text.append(
                        " - Reasoning effort level: none, minimal, low, medium, high, xhigh "
                        "(default: high)\n",
                        style="white",
                    )

        error_text.append("\nExample setup:\n", style="white")
        error_text.append("export STRIX_LLM='gpt-5.4'\n", style="dim white")

        if missing_optional_vars:
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append(
                        "export LLM_API_KEY='your-api-key-here'  "
                        "# not needed for local models, Vertex AI, AWS, etc.\n",
                        style="dim white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append(
                        "export LLM_API_BASE='http://localhost:11434'  "
                        "# needed for local models only\n",
                        style="dim white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append(
                        "export PERPLEXITY_API_KEY='your-perplexity-key-here'\n", style="dim white"
                    )
                elif var == "STRIX_REASONING_EFFORT":
                    error_text.append(
                        "export STRIX_REASONING_EFFORT='high'\n",
                        style="dim white",
                    )

        panel = Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        logger.error("Missing required env vars: %s", missing_required_vars)
        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)
    logger.info(
        "Environment OK (optional missing: %s)",
        missing_optional_vars or "none",
    )


def check_docker_installed() -> None:
    if shutil.which("docker") is None:
        logger.error("Docker CLI not found in PATH")
        console = Console()
        error_text = Text()
        error_text.append("DOCKER NOT INSTALLED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("The 'docker' CLI was not found in your PATH.\n", style="white")
        error_text.append(
            "Please install Docker and ensure the 'docker' command is available.\n\n", style="white"
        )

        panel = Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        sys.exit(1)
    logger.debug("Docker CLI present")


async def warm_up_llm() -> None:
    console = Console()
    logger.info("Warming up LLM connection")

    try:
        settings = load_settings()
        configure_sdk_model_defaults(settings)
        llm = settings.llm

        model = MultiProvider().get_model(normalize_model_name(llm.model or ""))
        await asyncio.wait_for(
            model.get_response(
                system_instructions="You are a helpful assistant.",
                input="Reply with just 'OK'.",
                model_settings=ModelSettings(),
                tools=[],
                output_schema=None,
                handoffs=[],
                tracing=ModelTracing.DISABLED,
                previous_response_id=None,
                conversation_id=None,
                prompt=None,
            ),
            timeout=llm.timeout,
        )
        logger.info("LLM warm-up succeeded for model %s", normalize_model_name(llm.model or ""))

    except Exception as e:
        logger.exception("LLM warm-up failed")
        error_text = Text()
        error_text.append("LLM CONNECTION FAILED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("Could not establish connection to the language model.\n", style="white")
        error_text.append("Please check your configuration and try again.\n", style="white")
        error_text.append(f"\nError: {e}", style="dim white")

        panel = Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)


def get_version() -> str:
    try:
        from importlib.metadata import version

        return version("strix-agent")
    except Exception:
        return "unknown"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Strix Multi-Agent Cybersecurity Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Web application penetration test
  strix --target https://example.com

  # GitHub repository analysis
  strix --target https://github.com/user/repo
  strix --target git@github.com:user/repo.git

  # Local code analysis
  strix --target ./my-project

  # Domain penetration test
  strix --target example.com

  # IP address penetration test
  strix --target 192.168.1.42

  # Multiple targets (e.g., white-box testing with source and deployed app)
  strix --target https://github.com/user/repo --target https://example.com
  strix --target ./my-project --target https://staging.example.com --target https://prod.example.com

  # Custom instructions (inline)
  strix --target example.com --instruction "Focus on authentication vulnerabilities"

  # Custom instructions (from file)
  strix --target example.com --instruction-file ./instructions.txt
  strix --target https://app.com --instruction-file /path/to/detailed_instructions.md
        """,
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"strix {get_version()}",
    )

    parser.add_argument(
        "-t",
        "--target",
        type=str,
        action="append",
        help="Target to test (URL, repository, local directory path, domain name, or IP address). "
        "Can be specified multiple times for multi-target scans. "
        "Required for fresh runs; loaded from disk when ``--resume`` is set.",
    )
    parser.add_argument(
        "--instruction",
        type=str,
        help="Custom instructions for the penetration test. This can be "
        "specific vulnerability types to focus on (e.g., 'Focus on IDOR and XSS'), "
        "testing approaches (e.g., 'Perform thorough authentication testing'), "
        "test credentials (e.g., 'Use the following credentials to access the app: "
        "admin:password123'), "
        "or areas of interest (e.g., 'Check login API endpoint for security issues').",
    )

    parser.add_argument(
        "--instruction-file",
        type=str,
        help="Path to a file containing detailed custom instructions for the penetration test. "
        "Use this option when you have lengthy or complex instructions saved in a file "
        "(e.g., '--instruction-file ./detailed_instructions.txt').",
    )

    parser.add_argument(
        "-n",
        "--non-interactive",
        action="store_true",
        help=(
            "Run in non-interactive mode (no TUI, exits on completion). "
            "Default is interactive mode with TUI."
        ),
    )

    parser.add_argument(
        "-m",
        "--scan-mode",
        type=str,
        choices=["quick", "standard", "deep"],
        default="deep",
        help=(
            "Scan mode: "
            "'quick' for fast CI/CD checks, "
            "'standard' for routine testing, "
            "'deep' for thorough security reviews (default). "
            "Default: deep."
        ),
    )

    parser.add_argument(
        "--scope-mode",
        type=str,
        choices=["auto", "diff", "full"],
        default="auto",
        help=(
            "Scope mode for code targets: "
            "'auto' enables PR diff-scope in CI/headless runs, "
            "'diff' forces changed-files scope, "
            "'full' disables diff-scope."
        ),
    )

    parser.add_argument(
        "--diff-base",
        type=str,
        help=(
            "Target branch or commit to compare against (e.g., origin/main). "
            "Defaults to the repository's default branch."
        ),
    )

    parser.add_argument(
        "--config",
        type=str,
        help="Path to a custom config file (JSON) to use instead of ~/.strix/cli-config.json",
    )

    parser.add_argument(
        "--resume",
        type=str,
        metavar="RUN_NAME",
        help=(
            "Resume a prior scan by its run name (the dir under ./strix_runs/). "
            "Picks up the root + every non-terminal subagent's full LLM history "
            "and agent topology. Skips fresh run-name generation."
        ),
    )

    args = parser.parse_args()

    if args.instruction and args.instruction_file:
        parser.error(
            "Cannot specify both --instruction and --instruction-file. Use one or the other."
        )

    if args.instruction_file:
        instruction_path = Path(args.instruction_file)
        try:
            with instruction_path.open(encoding="utf-8") as f:
                args.instruction = f.read().strip()
                if not args.instruction:
                    parser.error(f"Instruction file '{instruction_path}' is empty")
        except Exception as e:
            parser.error(f"Failed to read instruction file '{instruction_path}': {e}")

    args.user_explicit_instruction = args.instruction if args.resume else None

    if args.resume:
        if args.target:
            parser.error(
                "Cannot combine --resume with --target. --resume picks up where "
                "the prior run left off, including the original target list."
            )
        _load_resume_state(args, parser)
        agents_path = runtime_state_dir(run_dir_for(args.resume)) / "agents.json"
        if not agents_path.exists():
            parser.error(
                f"--resume {args.resume}: missing {agents_path}. The run was "
                f"persisted but never reached its first agent snapshot — "
                f"there's nothing to resume from. Pick a fresh --run-name "
                f"or remove --resume to start over with the same targets."
            )
    else:
        if not args.target:
            parser.error(
                "the following arguments are required: -t/--target "
                "(or use --resume <run_name> to continue a prior scan)"
            )
        args.targets_info = []
        for target in args.target:
            try:
                target_type, target_dict = infer_target_type(target)

                if target_type == "local_code":
                    display_target = target_dict.get("target_path", target)
                else:
                    display_target = target

                args.targets_info.append(
                    {"type": target_type, "details": target_dict, "original": display_target}
                )
            except ValueError:
                parser.error(f"Invalid target '{target}'")

        assign_workspace_subdirs(args.targets_info)
        rewrite_localhost_targets(args.targets_info, HOST_GATEWAY_HOSTNAME)
        check_existing_scans(args, parser)

    return args


def targets_match(t1: dict, t2: dict) -> bool:
    """Compare two targets by their type and normalized identifier values."""
    if not isinstance(t1, dict) or not isinstance(t2, dict):
        return False
    if t1.get("type") != t2.get("type"):
        return False
    t_type = t1.get("type")
    details1 = t1.get("details") or {}
    details2 = t2.get("details") or {}
    matched = False
    if t_type == "local_code":
        p1 = details1.get("target_path")
        p2 = details2.get("target_path")
        matched = bool(p1 and p2 and Path(p1).resolve() == Path(p2).resolve())
    elif t_type == "web_application":
        u1 = details1.get("target_url")
        u2 = details2.get("target_url")
        matched = bool(u1 and u2 and u1.strip().rstrip("/") == u2.strip().rstrip("/"))
    elif t_type == "repository":
        r1 = details1.get("target_repo")
        r2 = details2.get("target_repo")
        matched = bool(r1 and r2 and r1.strip() == r2.strip())
    elif t_type == "ip_address":
        i1 = details1.get("target_ip")
        i2 = details2.get("target_ip")
        matched = bool(i1 and i2 and i1.strip() == i2.strip())
    else:
        matched = str(t1.get("original")).strip() == str(t2.get("original")).strip()
    return matched


def find_previous_runs(targets_info: list[dict]) -> list[dict]:
    """Search strix_runs/ directory for any past runs that match the target list."""
    runs_dir = Path.cwd() / RUNS_DIR_NAME
    if not runs_dir.exists() or not runs_dir.is_dir():
        return []

    matching_runs = []
    for subdir in runs_dir.iterdir():
        if not subdir.is_dir():
            continue
        run_json_path = subdir / RUN_RECORD_FILENAME
        if not run_json_path.exists():
            continue
        try:
            with run_json_path.open("r", encoding="utf-8") as f:
                import json

                run_data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        prev_targets = run_data.get("targets_info", [])
        overlap = []
        for curr_t in targets_info:
            for prev_t in prev_targets:
                if targets_match(curr_t, prev_t):
                    overlap.append(curr_t)
                    break
        if overlap:
            matching_runs.append({"dir": subdir, "data": run_data, "overlap": overlap})

    def get_start_time(run_item: dict) -> datetime:
        st = run_item["data"].get("start_time")
        if st:
            try:
                clean_st = st.replace("Z", "+00:00")
                return datetime.fromisoformat(clean_st)
            except ValueError:
                pass
        return datetime.min.replace(tzinfo=UTC)

    matching_runs.sort(key=get_start_time, reverse=True)
    return matching_runs


def get_vulnerabilities_for_run(run_dir: Path) -> list[dict]:
    """Retrieve vulnerability findings list from vulnerabilities.json if it exists."""
    vulns_path = run_dir / "vulnerabilities.json"
    if vulns_path.exists():
        try:
            import json

            with vulns_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
        except (json.JSONDecodeError, OSError):
            pass
    return []


def check_existing_scans(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Check if the target has been previously scanned and prompt or advise the user."""
    if args.resume:
        return

    prev_runs = find_previous_runs(args.targets_info)
    if not prev_runs:
        return

    console = Console()
    most_recent = prev_runs[0]
    run_name = most_recent["data"].get("run_name", "unknown")
    status = most_recent["data"].get("status", "unknown")
    start_time_str = most_recent["data"].get("start_time", "")

    formatted_time = "unknown date"
    if start_time_str:
        try:
            dt = datetime.fromisoformat(start_time_str.replace("Z", "+00:00"))
            formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            formatted_time = start_time_str

    vulns = get_vulnerabilities_for_run(most_recent["dir"])

    info_text = Text()
    info_text.append("TARGET ALREADY SCANNED PREVIOUSLY\n\n", style="bold yellow")

    info_text.append("A previous scan for this target was found:\n", style="white")
    info_text.append("  • Run Name:  ", style="dim")
    info_text.append(f"{run_name}\n", style="bold white")
    info_text.append("  • Date:      ", style="dim")
    info_text.append(f"{formatted_time}\n", style="white")
    info_text.append("  • Status:    ", style="dim")

    status_style = {
        "completed": "bold green",
        "interrupted": "bold yellow",
        "failed": "bold red",
        "running": "bold cyan",
    }.get(status, "bold white")
    info_text.append(f"{status.upper()}\n", style=status_style)

    agents_path = runtime_state_dir(most_recent["dir"]) / "agents.json"
    is_resumeable = agents_path.exists()

    if vulns:
        info_text.append("  • Findings:  ", style="dim")
        severities = [v.get("severity", "unknown").lower() for v in vulns]
        crit = severities.count("critical")
        high = severities.count("high")
        med = severities.count("medium")
        low = severities.count("low")

        parts = []
        if crit:
            parts.append(f"[bold red]{crit} Critical[/]")
        if high:
            parts.append(f"[bold #f97316]{high} High[/]")
        if med:
            parts.append(f"[bold #eab308]{med} Medium[/]")
        if low:
            parts.append(f"[bold #3b82f6]{low} Low[/]")

        findings_str = ", ".join(parts) if parts else f"{len(vulns)} vulnerability/ies"
        info_text.append(f"{findings_str}\n", style="white")

        info_text.append("\n  [dim]Key Vulnerabilities Found:[/]\n")
        for v in vulns[:3]:
            title = v.get("title", "Untitled")
            sev = v.get("severity", "unknown").upper()
            sev_color = {
                "CRITICAL": "red",
                "HIGH": "#f97316",
                "MEDIUM": "#eab308",
                "LOW": "#3b82f6",
            }.get(sev, "white")
            info_text.append(f"    - [{sev_color}]{sev}[/]: {title}\n")
        if len(vulns) > 3:
            info_text.append(f"    - ... and {len(vulns) - 3} more.\n", style="dim")
    else:
        info_text.append("  • Findings:  ", style="dim")
        if status == "completed":
            info_text.append("No vulnerabilities identified.\n", style="green")
        else:
            msg = "No findings recorded (scan might have been interrupted).\n"
            info_text.append(msg, style="yellow")

    info_text.append("\nRecommended Next Steps & Checks:\n", style="bold #60a5fa")

    recommendation_index = 1
    if is_resumeable:
        if status != "completed":
            info_text.append(f"  {recommendation_index}. ", style="bold #60a5fa")
            info_text.append("Resume Scan: ", style="bold white")
            msg = "The last scan did not complete. Resume it to pick up where it left off.\n"
            info_text.append(msg, style="white")
        else:
            info_text.append(f"  {recommendation_index}. ", style="bold #60a5fa")
            info_text.append("Verify Findings: ", style="bold white")
            msg = (
                "Resume the scan and supply custom instructions to verify if the reported "
                "vulnerabilities have been patched (e.g. using --instruction 'Verify if "
                "vuln-0001 is fixed').\n"
            )
            info_text.append(msg, style="white")
        recommendation_index += 1

    info_text.append(f"  {recommendation_index}. ", style="bold #60a5fa")
    info_text.append("Scan with Deeper/Different Mode: ", style="bold white")
    prev_mode = most_recent["data"].get("scan_mode", "unknown")
    msg = f"Run a new scan using a different mode (previous run used '{prev_mode}').\n"
    info_text.append(msg, style="white")
    recommendation_index += 1

    info_text.append(f"  {recommendation_index}. ", style="bold #60a5fa")
    info_text.append("Start New Scan: ", style="bold white")
    info_text.append("Initiate a brand new, clean scan from scratch.\n", style="white")

    panel = Panel(
        info_text,
        title="[bold white]STRIX PRE-SCAN Check",
        title_align="left",
        border_style="yellow",
        padding=(1, 2),
    )

    console.print("\n")
    console.print(panel)
    console.print()

    if args.non_interactive:
        console.print(
            "[dim]Running in non-interactive mode. Proceeding with starting a new scan...[/]\n"
        )
        return

    console.print("[bold cyan]How would you like to proceed?[/]")
    if is_resumeable:
        console.print(
            f"  [bold]r[/]esume   - Resume the previous scan (run name: [bold]{run_name}[/])"
        )
    else:
        console.print(
            "  [dim]r[/][dim]esume   - (Disabled: no resumeable snapshot exists "
            "for the previous run)[/]"
        )
    console.print("  [bold]n[/]ew      - Start a new clean scan from scratch (default)")
    console.print("  [bold]c[/]ancel   - Cancel and exit")
    console.print()

    try:
        prompt_str = "r/" if is_resumeable else ""
        choice = input(f"Enter choice [{prompt_str}n/c] (default: n): ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[red]Cancelled by user.[/]")
        sys.exit(0)

    if choice == "c":
        console.print("[yellow]Scan cancelled.[/]")
        sys.exit(0)
    elif choice == "r" and is_resumeable:
        args.resume = run_name
        args.user_explicit_instruction = args.instruction
        _load_resume_state(args, parser)
        # Re-verify agents path just to be absolutely sure
        agents_path = runtime_state_dir(run_dir_for(args.resume)) / "agents.json"
        if not agents_path.exists():
            parser.error(f"--resume {args.resume}: missing {agents_path}.")
        console.print(f"[green]Resuming scan [bold]{run_name}[/]...[/]\n")
    else:
        console.print("[green]Starting a new scan...[/]\n")


def _persist_run_record(args: argparse.Namespace) -> None:
    run_dir = run_dir_for(args.run_name)
    run_dir.mkdir(parents=True, exist_ok=True)
    run_record = {
        "run_id": args.run_name,
        "run_name": args.run_name,
        "status": "running",
        "start_time": datetime.now(UTC).isoformat(),
        "end_time": None,
        "targets_info": args.targets_info,
        "scan_mode": args.scan_mode,
        "instruction": args.instruction,
        "non_interactive": args.non_interactive,
        "local_sources": getattr(args, "local_sources", []),
        "diff_scope": getattr(args, "diff_scope", {"active": False}),
        "scope_mode": args.scope_mode,
        "diff_base": args.diff_base,
    }
    write_run_record(run_dir, run_record)


def _load_resume_state(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Populate ``args.targets_info`` and friends from a prior run's run.json."""
    run_dir = run_dir_for(args.resume)
    state_path = run_dir / "run.json"
    if not state_path.exists():
        parser.error(
            f"--resume {args.resume}: no such run "
            f"(missing {state_path}; remove --resume for a fresh start)"
        )
    try:
        state = read_run_record(run_dir)
    except RuntimeError as exc:
        parser.error(f"--resume {args.resume}: run.json unreadable: {exc}")

    args.targets_info = state.get("targets_info") or []
    if not args.targets_info:
        parser.error(f"--resume {args.resume}: run.json has no targets_info")

    for target in args.targets_info:
        if not isinstance(target, dict):
            continue
        details = target.get("details") or {}
        if target.get("type") != "repository":
            continue
        cloned = details.get("cloned_repo_path")
        if not cloned:
            continue
        if not Path(cloned).expanduser().exists():
            parser.error(
                f"--resume {args.resume}: cloned repo at {cloned} is missing. "
                f"It was deleted between runs. Pick a fresh --run-name to "
                f"re-clone, or restore the directory before resuming."
            )

    if args.instruction is None:
        args.instruction = state.get("instruction")
    if state.get("local_sources"):
        args.local_sources = state.get("local_sources")
    if state.get("diff_scope"):
        args.diff_scope = state.get("diff_scope")
    persisted_scan_mode = state.get("scan_mode")
    if persisted_scan_mode and args.scan_mode == "deep":
        args.scan_mode = persisted_scan_mode


def display_completion_message(args: argparse.Namespace, results_path: Path) -> None:
    console = Console()
    report_state = get_global_report_state()

    scan_completed = False
    if report_state:
        scan_completed = report_state.run_record.get("status") == "completed"

    completion_text = Text()
    if scan_completed:
        completion_text.append("Penetration test completed", style="bold #22c55e")
    else:
        completion_text.append("SESSION ENDED", style="bold #eab308")

    target_text = Text()
    target_text.append("Target", style="dim")
    target_text.append("  ")
    if len(args.targets_info) == 1:
        target_text.append(args.targets_info[0]["original"], style="bold white")
    else:
        target_text.append(f"{len(args.targets_info)} targets", style="bold white")
        for target_info in args.targets_info:
            target_text.append("\n        ")
            target_text.append(target_info["original"], style="white")

    stats_text = build_final_stats_text(report_state)

    panel_parts: list[Text | str] = [completion_text, "\n\n", target_text]

    if stats_text.plain:
        panel_parts.extend(["\n", stats_text])

    results_text = Text()
    results_text.append("\n")
    results_text.append("Output", style="dim")
    results_text.append("  ")
    results_text.append(str(results_path), style="#60a5fa")
    panel_parts.extend(["\n", results_text])

    if not scan_completed:
        resume_text = Text()
        resume_text.append("\n")
        resume_text.append("Resume", style="dim")
        resume_text.append("  ")
        resume_text.append(f"strix --resume {args.run_name}", style="#22c55e")
        panel_parts.extend(["\n", resume_text])

    panel_content = Text.assemble(*panel_parts)

    border_style = "#22c55e" if scan_completed else "#eab308"

    panel = Panel(
        panel_content,
        title="[bold white]STRIX",
        title_align="left",
        border_style=border_style,
        padding=(1, 2),
    )

    console.print("\n")
    console.print(panel)
    console.print()
    console.print(
        "[#60a5fa]strix.ai[/]  [dim]·[/]  "
        "[#60a5fa]docs.strix.ai[/]  [dim]·[/]  "
        "[#60a5fa]discord.gg/strix-ai[/]"
    )
    console.print()


def pull_docker_image() -> None:
    console = Console()
    client = check_docker_connection()

    image = load_settings().runtime.image

    if image_exists(client, image):
        logger.debug("Docker image already present locally: %s", image)
        return

    logger.info("Pulling docker image: %s", image)
    console.print()
    console.print(f"[dim]Pulling image[/] {image}")
    console.print("[dim yellow]This only happens on first run and may take a few minutes...[/]")
    console.print()

    with console.status("[bold cyan]Downloading image layers...", spinner="dots") as status:
        try:
            layers_info: dict[str, str] = {}
            last_update = ""

            for line in client.api.pull(image, stream=True, decode=True):
                last_update = process_pull_line(line, layers_info, status, last_update)

        except DockerException as e:
            logger.exception("Failed to pull docker image %s", image)
            console.print()
            error_text = Text()
            error_text.append("FAILED TO PULL IMAGE", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(f"Could not download: {image}\n", style="white")
            error_text.append(str(e), style="dim red")

            panel = Panel(
                error_text,
                title="[bold white]STRIX",
                title_align="left",
                border_style="red",
                padding=(1, 2),
            )
            console.print(panel, "\n")
            sys.exit(1)

    logger.info("Docker image %s ready", image)
    success_text = Text()
    success_text.append("Docker image ready", style="#22c55e")
    console.print(success_text)
    console.print()


def main() -> None:
    configure_dependency_logging()

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    args = parse_arguments()

    if args.config:
        apply_config_override(validate_config_file(args.config))

    check_docker_installed()
    pull_docker_image()

    validate_environment()
    asyncio.run(warm_up_llm())

    persist_current()

    args.run_name = args.resume or generate_run_name(args.targets_info)

    if not args.resume:
        for target_info in args.targets_info:
            if target_info["type"] == "repository":
                repo_url = target_info["details"]["target_repo"]
                dest_name = target_info["details"].get("workspace_subdir")
                cloned_path = clone_repository(repo_url, args.run_name, dest_name)
                target_info["details"]["cloned_repo_path"] = cloned_path

        args.local_sources = collect_local_sources(args.targets_info)
        try:
            diff_scope = resolve_diff_scope_context(
                local_sources=args.local_sources,
                scope_mode=args.scope_mode,
                diff_base=args.diff_base,
                non_interactive=args.non_interactive,
            )
        except ValueError as e:
            console = Console()
            error_text = Text()
            error_text.append("DIFF SCOPE RESOLUTION FAILED", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(str(e), style="white")

            panel = Panel(
                error_text,
                title="[bold white]STRIX",
                title_align="left",
                border_style="red",
                padding=(1, 2),
            )
            console.print("\n")
            console.print(panel)
            console.print()
            sys.exit(1)

        args.diff_scope = diff_scope.metadata
        if diff_scope.instruction_block:
            if args.instruction:
                args.instruction = f"{diff_scope.instruction_block}\n\n{args.instruction}"
            else:
                args.instruction = diff_scope.instruction_block

        _persist_run_record(args)

    _telemetry_start_kwargs = {
        "model": load_settings().llm.model,
        "scan_mode": args.scan_mode,
        "is_whitebox": is_whitebox_scan(args.targets_info),
        "interactive": not args.non_interactive,
        "has_instructions": bool(args.instruction),
    }
    posthog.start(**_telemetry_start_kwargs)
    scarf.start(**_telemetry_start_kwargs)

    exit_reason = "user_exit"
    try:
        if args.non_interactive:
            asyncio.run(run_cli(args))
        else:
            asyncio.run(run_tui(args))
    except KeyboardInterrupt:
        exit_reason = "interrupted"
    except Exception as e:
        exit_reason = "error"
        posthog.error("unhandled_exception", str(e))
        scarf.error("unhandled_exception", str(e))
        raise
    finally:
        report_state = get_global_report_state()
        if report_state:
            status = {"interrupted": "interrupted", "error": "failed"}.get(
                exit_reason,
                "stopped",
            )
            report_state.cleanup(status=status)
            posthog.end(report_state, exit_reason=exit_reason)
            scarf.end(report_state, exit_reason=exit_reason)

    results_path = run_dir_for(args.run_name)
    display_completion_message(args, results_path)

    if args.non_interactive:
        report_state = get_global_report_state()
        if report_state and report_state.vulnerability_reports:
            sys.exit(2)


if __name__ == "__main__":
    main()
