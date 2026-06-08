import argparse
import asyncio
import atexit
import contextlib
import logging
import signal
import sys
import threading
from collections.abc import Callable
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar


if TYPE_CHECKING:
    from textual.timer import Timer

from rich.align import Align
from rich.console import Group
from rich.panel import Panel
from rich.style import Style
from rich.text import Span, Text
from textual import events, on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Label,
    ListItem,
    ListView,
    Markdown,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
    Tree,
)
from textual.widgets.tree import TreeNode

from strix.config import load_settings
from strix.core.runner import run_strix_scan
from strix.interface.tui.live_view import TuiLiveView
from strix.interface.tui.messages import send_user_message_to_agent
from strix.interface.tui.renderers import render_tool_widget
from strix.interface.tui.renderers.agent_message_renderer import AgentMessageRenderer
from strix.interface.tui.renderers.user_message_renderer import UserMessageRenderer
from strix.interface.utils import build_tui_stats_text
from strix.report.state import ReportState, set_global_report_state
from strix.runtime import session_manager


logger = logging.getLogger(__name__)


def get_package_version() -> str:
    try:
        return pkg_version("strix-agent")
    except PackageNotFoundError:
        return "dev"


class ChatTextArea(TextArea):  # type: ignore[misc]
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._app_reference: StrixTUIApp | None = None

    def set_app_reference(self, app: "StrixTUIApp") -> None:
        self._app_reference = app

    def on_mount(self) -> None:
        self._update_height()

    async def _on_key(self, event: events.Key) -> None:
        if event.key == "shift+enter":
            self.insert("\n")
            event.prevent_default()
            return

        if event.key == "enter" and self._app_reference:
            text_content = str(self.text)
            message = text_content.strip()
            if message:
                self.text = ""

                self._app_reference._send_user_message(message)

                event.prevent_default()
                return

        await super()._on_key(event)

    @on(TextArea.Changed)
    def _update_height(self, _event: TextArea.Changed | None = None) -> None:
        if not self.parent:
            return

        line_count = self.document.line_count
        target_lines = min(max(1, line_count), 8)

        new_height = target_lines + 2

        if self.parent.styles.height != new_height:
            self.parent.styles.height = new_height
            self.scroll_cursor_visible()


class SplashScreen(Static):
    ALLOW_SELECT = False
    PRIMARY_GREEN = "#22c55e"
    BANNER = (
        " ███████╗████████╗██████╗ ██╗██╗  ██╗\n"
        " ██╔════╝╚══██╔══╝██╔══██╗██║╚██╗██╔╝\n"
        " ███████╗   ██║   ██████╔╝██║ ╚███╔╝\n"
        " ╚════██║   ██║   ██╔══██╗██║ ██╔██╗\n"
        " ███████║   ██║   ██║  ██║██║██╔╝ ██╗\n"
        " ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝"
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._animation_step = 0
        self._animation_timer: Timer | None = None
        self._panel_static: Static | None = None
        self._version = "dev"

    def compose(self) -> ComposeResult:
        self._version = get_package_version()
        self._animation_step = 0
        start_line = self._build_start_line_text(self._animation_step)
        panel = self._build_panel(start_line)

        panel_static = Static(panel, id="splash_content")
        self._panel_static = panel_static
        yield panel_static

    def on_mount(self) -> None:
        self._animation_timer = self.set_interval(0.05, self._animate_start_line)

    def on_unmount(self) -> None:
        if self._animation_timer is not None:
            self._animation_timer.stop()
            self._animation_timer = None

    def _animate_start_line(self) -> None:
        if not self._panel_static:
            return

        self._animation_step += 1
        start_line = self._build_start_line_text(self._animation_step)
        panel = self._build_panel(start_line)
        self._panel_static.update(panel)

    def _build_panel(self, start_line: Text) -> Panel:
        content = Group(
            Align.center(Text(self.BANNER.strip("\n"), style=self.PRIMARY_GREEN, justify="center")),
            Align.center(Text(" ")),
            Align.center(self._build_welcome_text()),
            Align.center(self._build_version_text()),
            Align.center(self._build_tagline_text()),
            Align.center(Text(" ")),
            Align.center(start_line.copy()),
            Align.center(Text(" ")),
            Align.center(self._build_url_text()),
        )

        return Panel.fit(content, border_style=self.PRIMARY_GREEN, padding=(1, 6))

    def _build_url_text(self) -> Text:
        return Text("strix.ai", style=Style(color=self.PRIMARY_GREEN, bold=True))

    def _build_welcome_text(self) -> Text:
        text = Text("Welcome to ", style=Style(color="white", bold=True))
        text.append("Strix", style=Style(color=self.PRIMARY_GREEN, bold=True))
        text.append("!", style=Style(color="white", bold=True))
        return text

    def _build_version_text(self) -> Text:
        return Text(f"v{self._version}", style=Style(color="white", dim=True))

    def _build_tagline_text(self) -> Text:
        return Text("Open-source AI hackers for your apps", style=Style(color="white", dim=True))

    def _build_start_line_text(self, phase: int) -> Text:
        full_text = "Starting Strix Agent"
        text_len = len(full_text)

        shine_pos = phase % (text_len + 8)

        text = Text()
        for i, char in enumerate(full_text):
            dist = abs(i - shine_pos)

            if dist <= 1:
                style = Style(color="bright_white", bold=True)
            elif dist <= 3:
                style = Style(color="white", bold=True)
            elif dist <= 5:
                style = Style(color="#a3a3a3")
            else:
                style = Style(color="#525252")

            text.append(char, style=style)

        return text


class HelpScreen(ModalScreen[None]):
    def compose(self) -> ComposeResult:
        yield Grid(
            Label("Strix Help", id="help_title"),
            Label(
                "F1        Help\nCtrl+Q/C  Quit\nESC       Stop Agent\n"
                "Enter     Send message to agent\nTab       Switch panels\n↑/↓       Navigate tree",
                id="help_content",
            ),
            id="dialog",
        )

    def on_key(self, _event: events.Key) -> None:
        self.app.pop_screen()


class StopAgentScreen(ModalScreen[None]):
    def __init__(self, agent_name: str, agent_id: str):
        super().__init__()
        self.agent_name = agent_name
        self.agent_id = agent_id

    def compose(self) -> ComposeResult:
        yield Grid(
            Label(f"🛑 Stop '{self.agent_name}'?", id="stop_agent_title"),
            Grid(
                Button("Yes", variant="error", id="stop_agent"),
                Button("No", variant="default", id="cancel_stop"),
                id="stop_agent_buttons",
            ),
            id="stop_agent_dialog",
        )

    def on_mount(self) -> None:
        cancel_button = self.query_one("#cancel_stop", Button)
        cancel_button.focus()

    def on_key(self, event: events.Key) -> None:
        if event.key in ("left", "right", "up", "down"):
            focused = self.focused

            if focused and focused.id == "stop_agent":
                cancel_button = self.query_one("#cancel_stop", Button)
                cancel_button.focus()
            else:
                stop_button = self.query_one("#stop_agent", Button)
                stop_button.focus()

            event.prevent_default()
        elif event.key == "enter":
            focused = self.focused
            if focused and isinstance(focused, Button):
                focused.press()
            event.prevent_default()
        elif event.key == "escape":
            self.app.pop_screen()
            event.prevent_default()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.app.pop_screen()
        if event.button.id == "stop_agent":
            self.app.action_confirm_stop_agent(self.agent_id)


def build_vulnerability_markdown(vuln: dict[str, Any]) -> str:
    """Generate full markdown report for a vulnerability."""
    lines: list[str] = []

    title = vuln.get("title", "Untitled Vulnerability")
    lines.append(f"# {title}")
    lines.append("")

    if vuln.get("id"):
        lines.append(f"**ID:** {vuln['id']}")
    if vuln.get("severity"):
        lines.append(f"**Severity:** {vuln['severity'].upper()}")
    if vuln.get("timestamp"):
        lines.append(f"**Found:** {vuln['timestamp']}")
    if vuln.get("agent_name"):
        lines.append(f"**Agent:** {vuln['agent_name']}")
    if vuln.get("target"):
        lines.append(f"**Target:** {vuln['target']}")
    if vuln.get("endpoint"):
        lines.append(f"**Endpoint:** {vuln['endpoint']}")
    if vuln.get("method"):
        lines.append(f"**Method:** {vuln['method']}")
    if vuln.get("cve"):
        lines.append(f"**CVE:** {vuln['cve']}")
    if vuln.get("cvss") is not None:
        lines.append(f"**CVSS:** {vuln['cvss']}")

    cvss_breakdown = vuln.get("cvss_breakdown", {})
    if cvss_breakdown:
        abbrevs = {
            "attack_vector": "AV",
            "attack_complexity": "AC",
            "privileges_required": "PR",
            "user_interaction": "UI",
            "scope": "S",
            "confidentiality": "C",
            "integrity": "I",
            "availability": "A",
        }
        parts = [
            f"{abbrevs.get(k, k)}:{v}" for k, v in cvss_breakdown.items() if v and k in abbrevs
        ]
        if parts:
            lines.append(f"**CVSS Vector:** {'/'.join(parts)}")

    lines.append("")
    lines.append("## Description")
    lines.append("")
    lines.append(vuln.get("description") or "No description provided.")

    if vuln.get("impact"):
        lines.extend(["", "## Impact", "", vuln["impact"]])

    if vuln.get("technical_analysis"):
        lines.extend(["", "## Technical Analysis", "", vuln["technical_analysis"]])

    if vuln.get("poc_description") or vuln.get("poc_script_code"):
        lines.extend(["", "## Proof of Concept", ""])
        if vuln.get("poc_description"):
            lines.append(vuln["poc_description"])
            lines.append("")
        if vuln.get("poc_script_code"):
            lines.append("```python")
            lines.append(vuln["poc_script_code"])
            lines.append("```")

    if vuln.get("code_locations"):
        lines.extend(["", "## Code Analysis", ""])
        for i, loc in enumerate(vuln["code_locations"]):
            file_ref = loc.get("file", "unknown")
            line_ref = ""
            if loc.get("start_line") is not None:
                if loc.get("end_line") and loc["end_line"] != loc["start_line"]:
                    line_ref = f" (lines {loc['start_line']}-{loc['end_line']})"
                else:
                    line_ref = f" (line {loc['start_line']})"
            lines.append(f"**Location {i + 1}:** `{file_ref}`{line_ref}")
            if loc.get("label"):
                lines.append(f"  {loc['label']}")
            if loc.get("snippet"):
                lines.append(f"```\n{loc['snippet']}\n```")
            if loc.get("fix_before") or loc.get("fix_after"):
                lines.append("**Suggested Fix:**")
                lines.append("```diff")
                if loc.get("fix_before"):
                    lines.extend(f"- {line}" for line in loc["fix_before"].splitlines())
                if loc.get("fix_after"):
                    lines.extend(f"+ {line}" for line in loc["fix_after"].splitlines())
                lines.append("```")
            lines.append("")

    if vuln.get("remediation_steps"):
        lines.extend(["", "## Remediation", "", vuln["remediation_steps"]])

    return "\n".join(lines)


class VulnerabilityDetailScreen(ModalScreen[None]):
    SEVERITY_COLORS: ClassVar[dict[str, str]] = {
        "critical": "#dc2626",  # Red
        "high": "#ea580c",  # Orange
        "medium": "#d97706",  # Amber
        "low": "#22c55e",  # Green
        "info": "#3b82f6",  # Blue
    }

    FIELD_STYLE: ClassVar[str] = "bold #4ade80"

    def __init__(self, vulnerability: dict[str, Any]) -> None:
        super().__init__()
        self.vulnerability = vulnerability

    def compose(self) -> ComposeResult:
        content = self._render_vulnerability()
        yield Grid(
            VerticalScroll(Static(content, id="vuln_detail_content"), id="vuln_detail_scroll"),
            Horizontal(
                Button("Copy", variant="default", id="copy_vuln_detail"),
                Button("Done", variant="default", id="close_vuln_detail"),
                id="vuln_detail_buttons",
            ),
            id="vuln_detail_dialog",
        )

    def on_mount(self) -> None:
        close_button = self.query_one("#close_vuln_detail", Button)
        close_button.focus()

    def _get_cvss_color(self, cvss_score: float) -> str:
        if cvss_score >= 9.0:
            return "#dc2626"
        if cvss_score >= 7.0:
            return "#ea580c"
        if cvss_score >= 4.0:
            return "#d97706"
        if cvss_score >= 0.1:
            return "#65a30d"
        return "#6b7280"

    def _highlight_python(self, code: str) -> Text:
        try:
            from pygments.lexers import PythonLexer
            from pygments.styles import get_style_by_name

            lexer = PythonLexer()
            style = get_style_by_name("native")
            colors = {
                token: f"#{style_def['color']}" for token, style_def in style if style_def["color"]
            }

            text = Text()
            for token_type, token_value in lexer.get_tokens(code):
                if not token_value:
                    continue
                color = None
                tt = token_type
                while tt:
                    if tt in colors:
                        color = colors[tt]
                        break
                    tt = tt.parent
                text.append(token_value, style=color)
        except (ImportError, KeyError, AttributeError):
            return Text(code)
        else:
            return text

    def _render_vulnerability(self) -> Text:
        vuln = self.vulnerability
        text = Text()

        text.append("🐞 ")
        text.append("Vulnerability Report", style="bold #ea580c")

        agent_name = vuln.get("agent_name", "")
        if agent_name:
            text.append("\n\n")
            text.append("Agent: ", style=self.FIELD_STYLE)
            text.append(agent_name)

        title = vuln.get("title", "")
        if title:
            text.append("\n\n")
            text.append("Title: ", style=self.FIELD_STYLE)
            text.append(title)

        severity = vuln.get("severity", "")
        if severity:
            text.append("\n\n")
            text.append("Severity: ", style=self.FIELD_STYLE)
            severity_color = self.SEVERITY_COLORS.get(severity.lower(), "#6b7280")
            text.append(severity.upper(), style=f"bold {severity_color}")

        cvss_score = vuln.get("cvss")
        if cvss_score is not None:
            text.append("\n\n")
            text.append("CVSS Score: ", style=self.FIELD_STYLE)
            cvss_color = self._get_cvss_color(float(cvss_score))
            text.append(str(cvss_score), style=f"bold {cvss_color}")

        target = vuln.get("target", "")
        if target:
            text.append("\n\n")
            text.append("Target: ", style=self.FIELD_STYLE)
            text.append(target)

        endpoint = vuln.get("endpoint", "")
        if endpoint:
            text.append("\n\n")
            text.append("Endpoint: ", style=self.FIELD_STYLE)
            text.append(endpoint)

        method = vuln.get("method", "")
        if method:
            text.append("\n\n")
            text.append("Method: ", style=self.FIELD_STYLE)
            text.append(method)

        cve = vuln.get("cve", "")
        if cve:
            text.append("\n\n")
            text.append("CVE: ", style=self.FIELD_STYLE)
            text.append(cve)

        cvss_breakdown = vuln.get("cvss_breakdown", {})
        if cvss_breakdown:
            cvss_parts = []
            if cvss_breakdown.get("attack_vector"):
                cvss_parts.append(f"AV:{cvss_breakdown['attack_vector']}")
            if cvss_breakdown.get("attack_complexity"):
                cvss_parts.append(f"AC:{cvss_breakdown['attack_complexity']}")
            if cvss_breakdown.get("privileges_required"):
                cvss_parts.append(f"PR:{cvss_breakdown['privileges_required']}")
            if cvss_breakdown.get("user_interaction"):
                cvss_parts.append(f"UI:{cvss_breakdown['user_interaction']}")
            if cvss_breakdown.get("scope"):
                cvss_parts.append(f"S:{cvss_breakdown['scope']}")
            if cvss_breakdown.get("confidentiality"):
                cvss_parts.append(f"C:{cvss_breakdown['confidentiality']}")
            if cvss_breakdown.get("integrity"):
                cvss_parts.append(f"I:{cvss_breakdown['integrity']}")
            if cvss_breakdown.get("availability"):
                cvss_parts.append(f"A:{cvss_breakdown['availability']}")
            if cvss_parts:
                text.append("\n\n")
                text.append("CVSS Vector: ", style=self.FIELD_STYLE)
                text.append("/".join(cvss_parts), style="dim")

        description = vuln.get("description", "")
        if description:
            text.append("\n\n")
            text.append("Description", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(description)

        impact = vuln.get("impact", "")
        if impact:
            text.append("\n\n")
            text.append("Impact", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(impact)

        technical_analysis = vuln.get("technical_analysis", "")
        if technical_analysis:
            text.append("\n\n")
            text.append("Technical Analysis", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(technical_analysis)

        poc_description = vuln.get("poc_description", "")
        if poc_description:
            text.append("\n\n")
            text.append("PoC Description", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(poc_description)

        poc_script_code = vuln.get("poc_script_code", "")
        if poc_script_code:
            text.append("\n\n")
            text.append("PoC Code", style=self.FIELD_STYLE)
            text.append("\n")
            text.append_text(self._highlight_python(poc_script_code))

        remediation_steps = vuln.get("remediation_steps", "")
        if remediation_steps:
            text.append("\n\n")
            text.append("Remediation", style=self.FIELD_STYLE)
            text.append("\n")
            text.append(remediation_steps)

        return text

    def _get_markdown_report(self) -> str:
        """Get Markdown version of vulnerability report for clipboard."""
        return build_vulnerability_markdown(self.vulnerability)

    def on_key(self, event: events.Key) -> None:
        if event.key == "escape":
            self.app.pop_screen()
            event.prevent_default()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "copy_vuln_detail":
            markdown_text = self._get_markdown_report()
            self.app.copy_to_clipboard(markdown_text)

            copy_button = self.query_one("#copy_vuln_detail", Button)
            copy_button.label = "Copied!"
            self.set_timer(1.5, lambda: setattr(copy_button, "label", "Copy"))
        elif event.button.id == "close_vuln_detail":
            self.app.pop_screen()


class VulnerabilityItem(Static):
    def __init__(self, label: Text, vuln_data: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(label, **kwargs)
        self.vuln_data = vuln_data

    def on_click(self, _event: events.Click) -> None:
        """Handle click to open vulnerability detail."""
        self.app.push_screen(VulnerabilityDetailScreen(self.vuln_data))


class VulnerabilityReportItem(ListItem):
    def __init__(self, vuln_data: dict[str, Any], label: Text, **kwargs: Any) -> None:
        super().__init__(Static(label), **kwargs)
        self.vuln_data = vuln_data


class VulnerabilitiesPanel(VerticalScroll):
    SEVERITY_COLORS: ClassVar[dict[str, str]] = {
        "critical": "#dc2626",  # Red
        "high": "#ea580c",  # Orange
        "medium": "#d97706",  # Amber
        "low": "#22c55e",  # Green
        "info": "#3b82f6",  # Blue
    }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._vulnerabilities: list[dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        return []

    def update_vulnerabilities(self, vulnerabilities: list[dict[str, Any]]) -> None:
        """Update the list of vulnerabilities and re-render."""
        if self._vulnerabilities == vulnerabilities:
            return
        self._vulnerabilities = list(vulnerabilities)
        self._render_panel()

    def _render_panel(self) -> None:
        """Render the vulnerabilities panel content."""
        for child in list(self.children):
            if isinstance(child, VulnerabilityItem):
                child.remove()

        if not self._vulnerabilities:
            return

        for vuln in self._vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            title = vuln.get("title", "Unknown Vulnerability")
            color = self.SEVERITY_COLORS.get(severity, "#3b82f6")

            label = Text()
            label.append("● ", style=Style(color=color))
            label.append(title, style=Style(color="#d4d4d4"))

            item = VulnerabilityItem(label, vuln, classes="vuln-item")
            self.mount(item)


class QuitScreen(ModalScreen[None]):
    def compose(self) -> ComposeResult:
        yield Grid(
            Label("Quit Strix?", id="quit_title"),
            Grid(
                Button("Yes", variant="error", id="quit"),
                Button("No", variant="default", id="cancel"),
                id="quit_buttons",
            ),
            id="quit_dialog",
        )

    def on_mount(self) -> None:
        cancel_button = self.query_one("#cancel", Button)
        cancel_button.focus()

    def on_key(self, event: events.Key) -> None:
        if event.key in ("left", "right", "up", "down"):
            focused = self.focused

            if focused and focused.id == "quit":
                cancel_button = self.query_one("#cancel", Button)
                cancel_button.focus()
            else:
                quit_button = self.query_one("#quit", Button)
                quit_button.focus()

            event.prevent_default()
        elif event.key == "enter":
            focused = self.focused
            if focused and isinstance(focused, Button):
                focused.press()
            event.prevent_default()
        elif event.key == "escape":
            self.app.pop_screen()
            event.prevent_default()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "quit":
            self.app.action_custom_quit()
        else:
            self.app.pop_screen()


class StrixTUIApp(App[None]):
    CSS_PATH = str(Path(__file__).resolve().parent.parent / "assets" / "tui_styles.tcss")
    ALLOW_SELECT = True

    SIDEBAR_MIN_WIDTH = 120

    selected_agent_id: reactive[str | None] = reactive(default=None)
    show_splash: reactive[bool] = reactive(default=True)

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("f1", "toggle_help", "Help", priority=True),
        Binding("ctrl+q", "request_quit", "Quit", priority=True),
        Binding("ctrl+c", "request_quit", "Quit", priority=True),
        Binding("escape", "stop_selected_agent", "Stop Agent", priority=True),
    ]

    def __init__(self, args: argparse.Namespace):
        super().__init__()
        self.args = args
        self.scan_config = self._build_scan_config(args)

        self.report_state = ReportState(self.scan_config["run_name"])
        self.report_state.hydrate_from_run_dir()
        self.report_state.set_scan_config(self.scan_config)
        self.report_state.save_run_data()
        set_global_report_state(self.report_state)
        self.live_view = TuiLiveView()
        self.live_view.hydrate_from_run_dir(self.report_state.get_run_dir())
        self._agent_graph_sync_future: Any | None = None

        from strix.core.agents import AgentCoordinator

        self.coordinator = AgentCoordinator()

        self.agent_nodes: dict[str, TreeNode[Any]] = {}

        self._displayed_agents: set[str] = set()
        self._displayed_events: list[str] = []

        self._scan_thread: threading.Thread | None = None
        self._scan_loop: asyncio.AbstractEventLoop | None = None
        self._scan_stop_event = threading.Event()
        self._scan_completed = threading.Event()
        self._scan_error: BaseException | None = None

        self._spinner_frame_index: int = 0
        self._sweep_num_squares: int = 6
        self._sweep_colors: list[str] = [
            "#000000",  # Dimmest (shows dot)
            "#031a09",
            "#052e16",
            "#0d4a2a",
            "#15803d",
            "#22c55e",
            "#4ade80",
            "#86efac",  # Brightest
        ]
        self._dot_animation_timer: Any | None = None

        self._caido_stats_future: Any | None = None
        self._caido_request_count: int = 0
        self._caido_sitemap_count: int = 0

        self._setup_cleanup_handlers()

    def _build_scan_config(self, args: argparse.Namespace) -> dict[str, Any]:
        return {
            "scan_id": args.run_name,
            "targets": args.targets_info,
            "user_instructions": args.instruction or "",
            "run_name": args.run_name,
            "diff_scope": getattr(args, "diff_scope", {"active": False}),
            "scan_mode": getattr(args, "scan_mode", "deep"),
            "non_interactive": bool(getattr(args, "non_interactive", False)),
            "local_sources": getattr(args, "local_sources", None) or [],
            "scope_mode": getattr(args, "scope_mode", "auto"),
            "diff_base": getattr(args, "diff_base", None),
            "resume_instruction": getattr(args, "user_explicit_instruction", None) or "",
        }

    def _setup_cleanup_handlers(self) -> None:
        def cleanup_on_exit() -> None:
            self.report_state.cleanup()

        def signal_handler(_signum: int, _frame: Any) -> None:
            self.report_state.cleanup(status="interrupted")
            sys.exit(0)

        atexit.register(cleanup_on_exit)
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, signal_handler)

    def compose(self) -> ComposeResult:
        if self.show_splash:
            yield SplashScreen(id="splash_screen")

    async def watch_show_splash(self, show_splash: bool) -> None:
        if not show_splash and self._is_mounted:
            try:
                splash = self.query_one("#splash_screen")
                splash.remove()
            except Exception:
                logger.debug("Splash screen not found or already removed")

            main_container = Vertical(id="main_container")
            await self.mount(main_container)

            tabbed_content = TabbedContent(id="tui_tabs")
            await main_container.mount(tabbed_content)

            # Tab 0: Dashboard
            dashboard_pane = TabPane("Dashboard", id="dashboard_tab")
            await tabbed_content.add_pane(dashboard_pane)

            db_container = Horizontal(id="dashboard_container")
            await dashboard_pane.mount(db_container)

            db_stats_panel = Vertical(id="dashboard_stats_panel")
            db_agents_panel = Vertical(id="dashboard_agents_panel")
            await db_container.mount(db_stats_panel)
            await db_container.mount(db_agents_panel)

            db_progress_card = Static("", id="db_progress_card")
            db_vuln_card = Static("", id="db_vuln_card")
            db_crawled_card = Static("", id="db_crawled_card")
            db_usage_card = Static("", id="db_usage_card")

            db_progress_card.border_title = "Scan Progress & Target"
            db_vuln_card.border_title = "Vulnerabilities Found"
            db_crawled_card.border_title = "Crawled Data"
            db_usage_card.border_title = "Model & LLM Cost"

            await db_stats_panel.mount(db_progress_card)
            await db_stats_panel.mount(db_vuln_card)
            await db_stats_panel.mount(db_crawled_card)
            await db_stats_panel.mount(db_usage_card)

            db_agents_card = Static("", id="db_agents_card")
            db_agents_scroll = VerticalScroll(db_agents_card, id="db_agents_scroll")
            db_agents_card_container = Vertical(db_agents_scroll, id="db_agents_card_container")
            db_agents_card_container.border_title = "Active Subagents"

            await db_agents_panel.mount(db_agents_card_container)

            # Tab 1: Chat / Console
            chat_pane = TabPane("Chat & Agents", id="chat_tab")
            await tabbed_content.add_pane(chat_pane)

            content_container = Horizontal(id="content_container")
            await chat_pane.mount(content_container)

            chat_area_container = Vertical(id="chat_area_container")

            chat_display = Static("", id="chat_display")
            chat_history = VerticalScroll(chat_display, id="chat_history")
            chat_history.can_focus = True

            status_text = Static("", id="status_text")
            status_text.ALLOW_SELECT = False
            keymap_indicator = Static("", id="keymap_indicator")
            keymap_indicator.ALLOW_SELECT = False

            agent_status_display = Horizontal(
                status_text, keymap_indicator, id="agent_status_display", classes="hidden"
            )

            chat_prompt = Static("> ", id="chat_prompt")
            chat_prompt.ALLOW_SELECT = False
            chat_input = ChatTextArea(
                "",
                id="chat_input",
                show_line_numbers=False,
            )
            chat_input.set_app_reference(self)
            chat_input_container = Horizontal(chat_prompt, chat_input, id="chat_input_container")

            agents_tree: Tree[Any] = Tree("Agents", id="agents_tree")
            agents_tree.root.expand()
            agents_tree.show_root = False

            agents_tree.show_guides = True
            agents_tree.guide_depth = 3

            stats_display = Static("", id="stats_display")
            stats_scroll = VerticalScroll(stats_display, id="stats_scroll")

            vulnerabilities_panel = VulnerabilitiesPanel(id="vulnerabilities_panel")

            sidebar = Vertical(agents_tree, vulnerabilities_panel, stats_scroll, id="sidebar")

            await content_container.mount(chat_area_container)
            await content_container.mount(sidebar)

            await chat_area_container.mount(chat_history)
            await chat_area_container.mount(agent_status_display)
            await chat_area_container.mount(chat_input_container)

            # Tab 2: Vulnerabilities Database
            vulns_tab_list = ListView(id="vulns_tab_list")
            vulns_tab_markdown = Markdown(id="vulns_tab_markdown")
            vulns_tab_markdown_container = VerticalScroll(
                vulns_tab_markdown, id="vulns_tab_markdown_container"
            )

            vulns_tab_container = Horizontal(
                vulns_tab_list, vulns_tab_markdown_container, id="vulns_tab_container"
            )

            vulnerabilities_pane = TabPane("Vulnerabilities", id="vulnerabilities_tab")
            await tabbed_content.add_pane(vulnerabilities_pane)
            await vulnerabilities_pane.mount(vulns_tab_container)

            self.call_after_refresh(self._focus_chat_input)

    def _focus_chat_input(self) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self._is_mounted:
            return

        try:
            chat_input = self.query_one("#chat_input", ChatTextArea)
            chat_input.show_vertical_scrollbar = False
            chat_input.show_horizontal_scrollbar = False
            chat_input.focus()
        except (ValueError, Exception):
            self.call_after_refresh(self._focus_chat_input)

    def _focus_agents_tree(self) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self._is_mounted:
            return

        try:
            agents_tree = self.query_one("#agents_tree", Tree)
            agents_tree.focus()

            if agents_tree.root.children:
                first_node = agents_tree.root.children[0]
                agents_tree.select_node(first_node)
        except (ValueError, Exception):
            self.call_after_refresh(self._focus_agents_tree)

    def on_mount(self) -> None:
        self.title = "strix"

        self.set_timer(4.5, self._hide_splash_screen)

    def _hide_splash_screen(self) -> None:
        self.show_splash = False

        self._start_scan_thread()

        self.set_interval(0.35, self._update_ui)

    def _update_ui(self) -> None:
        if self.show_splash:
            return

        if len(self.screen_stack) > 1:
            return

        if not self._is_mounted:
            return

        try:
            self._sync_agent_graph()
        except Exception:
            logger.exception("Failed to sync agent graph")

        try:
            self._sync_caido_stats()
        except Exception:
            logger.exception("Failed to sync caido stats")

        try:
            for agent_id, agent_data in list(self.live_view.agents.items()):
                if agent_id not in self._displayed_agents:
                    if self._add_agent_node(agent_data):
                        self._displayed_agents.add(agent_id)
                else:
                    self._update_agent_node(agent_id, agent_data)
        except Exception:
            logger.exception("Failed to update agent nodes")

        try:
            self._update_chat_view()
        except Exception:
            logger.exception("Failed to update chat view")

        try:
            self._update_agent_status_display()
        except Exception:
            logger.exception("Failed to update agent status display")

        try:
            self._update_stats_display()
        except Exception:
            logger.exception("Failed to update stats display")

        try:
            self._update_vulnerabilities_panel()
        except Exception:
            logger.exception("Failed to update vulnerabilities panel")

        try:
            self._update_vulnerabilities_tab_view()
        except Exception:
            logger.exception("Failed to update vulnerabilities tab view")

        try:
            self._update_dashboard()
        except Exception:
            logger.exception("Failed to update dashboard")

    def _sync_agent_graph(self) -> None:
        future = self._agent_graph_sync_future
        if future is not None:
            if not future.done():
                if self._scan_loop is not None and self._scan_loop.is_closed():
                    future.cancel()
                    self._agent_graph_sync_future = None
                else:
                    return
            else:
                self._agent_graph_sync_future = None
                try:
                    parent_of, statuses, names, metadata = future.result()
                except Exception:
                    logger.exception("TUI agent graph sync failed")
                else:
                    for agent_id, status in statuses.items():
                        self.live_view.upsert_agent(
                            agent_id,
                            name=names.get(agent_id, agent_id),
                            parent_id=parent_of.get(agent_id),
                            status=status,
                            metadata=metadata.get(agent_id),
                        )

        if self._scan_loop is None or self._scan_loop.is_closed():
            return

        async def collect() -> tuple[
            dict[str, str | None],
            dict[str, Any],
            dict[str, str],
            dict[str, dict[str, Any]],
        ]:
            return await self.coordinator.graph_snapshot()

        self._agent_graph_sync_future = asyncio.run_coroutine_threadsafe(collect(), self._scan_loop)

    def _sync_caido_stats(self) -> None:
        future = self._caido_stats_future
        if future is not None:
            if not future.done():
                if self._scan_loop is not None and self._scan_loop.is_closed():
                    future.cancel()
                    self._caido_stats_future = None
                else:
                    return
            else:
                self._caido_stats_future = None
                try:
                    req_count, sitemap_count = future.result()
                except Exception:
                    logger.debug("TUI caido stats sync failed")
                else:
                    self._caido_request_count = req_count
                    self._caido_sitemap_count = sitemap_count

        if self._scan_loop is None or self._scan_loop.is_closed():
            return

        async def fetch_stats() -> tuple[int, int]:
            bundle = session_manager._SESSION_CACHE.get(self.scan_config["run_name"])
            client = bundle.get("caido_client") if bundle else None
            if not client:
                return 0, 0

            # Query request count
            req_count = 0
            with contextlib.suppress(Exception):
                res = await client.graphql.query("""
                    query {
                        requests(first: 1) {
                            count {
                                value
                            }
                        }
                    }
                """)
                req_count = res.get("requests", {}).get("count", {}).get("value", 0)

            # Query sitemap count
            sitemap_count = 0
            with contextlib.suppress(Exception):
                res = await client.graphql.query("""
                    query {
                        sitemapRootEntries {
                            count {
                                value
                            }
                        }
                    }
                """)
                sitemap_count = res.get("sitemapRootEntries", {}).get("count", {}).get("value", 0)

            return req_count, sitemap_count

        self._caido_stats_future = asyncio.run_coroutine_threadsafe(fetch_stats(), self._scan_loop)

    def _update_dashboard(self) -> None:
        # 1. Progress Card
        try:
            db_progress_card = self.query_one("#db_progress_card", Static)
            if self._is_widget_safe(db_progress_card):
                targets = []
                for t in self.scan_config.get("targets", []):
                    target_str = (
                        t.get("original")
                        or t.get("details", {}).get("target_url")
                        or "unknown"
                    )
                    targets.append(target_str)
                targets_str = ", ".join(targets)

                from datetime import UTC, datetime
                try:
                    start_dt = datetime.fromisoformat(self.report_state.start_time)
                    if self.report_state.end_time:
                        end_dt = datetime.fromisoformat(self.report_state.end_time)
                        elapsed = end_dt - start_dt
                    else:
                        elapsed = datetime.now(UTC) - start_dt
                    seconds = int(elapsed.total_seconds())
                    hours, remainder = divmod(seconds, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    elapsed_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                except Exception:
                    elapsed_str = "00:00:00"

                status = self.report_state.run_record.get("status", "running")
                status_colors = {
                    "running": "bold #3b82f6",
                    "completed": "bold #22c55e",
                    "failed": "bold #ef4444",
                    "stopped": "bold #737373",
                    "interrupted": "bold #f59e0b",
                }
                status_color = status_colors.get(status.lower(), "bold white")
                mode = self.scan_config.get("scan_mode", "deep").upper()

                progress_text = Text()
                progress_text.append("Target:    ", style="bold #a8a29e")
                progress_text.append(targets_str, style="white")
                progress_text.append("\nStatus:    ", style="bold #a8a29e")
                progress_text.append(status.upper(), style=status_color)
                progress_text.append("\nMode:      ", style="bold #a8a29e")
                progress_text.append(mode, style="white")
                progress_text.append("\nDuration:  ", style="bold #a8a29e")
                progress_text.append(elapsed_str, style="white")
                self._safe_widget_operation(db_progress_card.update, progress_text)
        except Exception as e:
            logger.debug("Failed to update progress card: %s", e)

        # 2. Vulnerability Card
        try:
            db_vuln_card = self.query_one("#db_vuln_card", Static)
            if self._is_widget_safe(db_vuln_card):
                vulns = self.report_state.vulnerability_reports
                vuln_count = len(vulns)
                severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                for v in vulns:
                    sev = v.get("severity", "info").lower()
                    if sev in severity_counts:
                        severity_counts[sev] += 1

                vuln_text = Text()
                vuln_text.append("Total Findings: ", style="bold #a8a29e")
                vuln_text.append(str(vuln_count), style="bold white")
                vuln_text.append("\n\n")

                sevs = [
                    ("critical", "CRITICAL", "#dc2626"),
                    ("high", "HIGH", "#ea580c"),
                    ("medium", "MEDIUM", "#d97706"),
                    ("low", "LOW", "#22c55e"),
                    ("info", "INFO", "#3b82f6"),
                ]
                parts = []
                for key, name, color in sevs:
                    count = severity_counts[key]
                    part = Text()
                    part.append(f" {name}: ", style=f"bold {color}")
                    part.append(str(count), style="bold white")
                    parts.append(part)

                for i, part in enumerate(parts):
                    vuln_text.append_text(part)
                    if i < len(parts) - 1:
                        vuln_text.append("  |  ", style="dim white")
                self._safe_widget_operation(db_vuln_card.update, vuln_text)
        except Exception as e:
            logger.debug("Failed to update vuln card: %s", e)

        # 3. Crawled Data Card
        try:
            db_crawled_card = self.query_one("#db_crawled_card", Static)
            if self._is_widget_safe(db_crawled_card):
                crawled_text = Text()
                crawled_text.append("HTTP Requests captured: ", style="bold #a8a29e")
                crawled_text.append(str(self._caido_request_count), style="white")
                crawled_text.append("\nSitemap Domains:        ", style="bold #a8a29e")
                crawled_text.append(str(self._caido_sitemap_count), style="white")
                caido_url = getattr(self.report_state, "caido_url", None)
                if caido_url:
                    crawled_text.append("\nCaido Console URL:      ", style="bold #a8a29e")
                    crawled_text.append(caido_url, style="bold #3b82f6")
                self._safe_widget_operation(db_crawled_card.update, crawled_text)
        except Exception as e:
            logger.debug("Failed to update crawled data card: %s", e)

        # 4. Model & LLM Cost Card
        try:
            db_usage_card = self.query_one("#db_usage_card", Static)
            if self._is_widget_safe(db_usage_card):
                model = load_settings().llm.model or "unknown"
                usage = self.report_state.get_total_llm_usage()
                cost = usage.get("cost", 0.0)
                total_tokens = usage.get("total_tokens", 0)
                input_tokens = usage.get("input_tokens", 0)
                output_tokens = usage.get("output_tokens", 0)

                usage_text = Text()
                usage_text.append("Model:          ", style="bold #a8a29e")
                usage_text.append(str(model), style="white")
                usage_text.append("\nEstimated Cost: ", style="bold #a8a29e")
                usage_text.append(f"${cost:.4f}", style="bold #fbbf24")
                usage_text.append("\nToken Usage:    ", style="bold #a8a29e")
                usage_text.append(
                    f"Input: {input_tokens:,} | "
                    f"Output: {output_tokens:,} | "
                    f"Total: {total_tokens:,}",
                    style="white",
                )
                self._safe_widget_operation(db_usage_card.update, usage_text)
        except Exception as e:
            logger.debug("Failed to update usage card: %s", e)

        # 5. Active Subagents Card
        try:
            db_agents_card = self.query_one("#db_agents_card", Static)
            if self._is_widget_safe(db_agents_card):
                agents_text = Text()
                active_agents = []
                for agent_id, agent_data in self.live_view.agents.items():
                    status = agent_data.get("status", "running")
                    if status in ["running", "waiting"]:
                        active_agents.append((agent_id, agent_data))

                if not active_agents:
                    agents_text.append(
                        "No active subagents currently executing.",
                        style="italic #737373",
                    )
                else:
                    for i, (_, agent_data) in enumerate(active_agents):
                        name = agent_data.get("name", "Unknown Agent")
                        status = agent_data.get("status", "running")
                        metadata = agent_data.get("metadata", {})
                        task = metadata.get("task", "")

                        status_icon = "⚪" if status == "running" else "⏸"
                        status_color = "#3b82f6" if status == "running" else "#fbbf24"

                        if i > 0:
                            agents_text.append("\n")
                        agents_text.append(f"{status_icon} ", style=f"bold {status_color}")
                        agents_text.append(f"{name} ", style="bold white")
                        agents_text.append(f"[{status}]", style=f"dim {status_color}")
                        if task:
                            agents_text.append("\n   Task: ", style="bold #a8a29e")
                            agents_text.append(task, style="white")
                        agents_text.append("\n")
                self._safe_widget_operation(db_agents_card.update, agents_text)
        except Exception as e:
            logger.debug("Failed to update agents card: %s", e)

    def _update_agent_node(self, agent_id: str, agent_data: dict[str, Any]) -> bool:
        if agent_id not in self.agent_nodes:
            return False

        try:
            agent_node = self.agent_nodes[agent_id]
            agent_name_raw = agent_data.get("name", "Agent")
            status = agent_data.get("status", "running")

            status_indicators = {
                "running": "⚪",
                "waiting": "⏸",
                "completed": "🟢",
                "failed": "🔴",
                "stopped": "■",
            }

            status_icon = status_indicators.get(status, "○")
            vuln_count = self._agent_vulnerability_count(agent_id)
            vuln_indicator = f" ({vuln_count})" if vuln_count > 0 else ""

            metadata = agent_data.get("metadata", {})
            task = metadata.get("task", "")
            task_suffix = f" [{task[:20]}...]" if len(task) > 20 else f" [{task}]" if task else ""
            agent_name = f"{status_icon} {agent_name_raw}{vuln_indicator}{task_suffix}"

            if agent_node.label != agent_name:
                agent_node.set_label(agent_name)
                return True

        except (KeyError, AttributeError, ValueError) as e:
            logger.warning(f"Failed to update agent node label: {e}")

        return False

    def _get_chat_content(
        self,
    ) -> tuple[Any, str | None]:
        if not self.selected_agent_id:
            return self._get_chat_placeholder_content("Loading...", "placeholder-no-agent")

        events = self._gather_agent_events(self.selected_agent_id)

        if not events:
            return self._get_chat_placeholder_content(
                "Starting agent...", "placeholder-no-activity"
            )

        current_event_ids = [f"{e['id']}:{e.get('version', 0)}" for e in events]
        if current_event_ids == self._displayed_events:
            return None, None

        self._displayed_events = current_event_ids
        return self._get_rendered_events_content(events), "chat-content"

    def _update_chat_view(self) -> None:
        if len(self.screen_stack) > 1 or self.show_splash or not self._is_mounted:
            return

        try:
            chat_history = self.query_one("#chat_history", VerticalScroll)
        except (ValueError, Exception):
            return

        if not self._is_widget_safe(chat_history):
            return

        try:
            is_at_bottom = chat_history.scroll_y >= chat_history.max_scroll_y
        except (AttributeError, ValueError):
            is_at_bottom = True

        content, css_class = self._get_chat_content()
        if content is None:
            return

        chat_display = self.query_one("#chat_display", Static)
        self._safe_widget_operation(chat_display.update, content)
        chat_display.set_classes(css_class or "")

        if is_at_bottom:
            self.call_later(chat_history.scroll_end, animate=False)

    def _get_chat_placeholder_content(
        self, message: str, placeholder_class: str
    ) -> tuple[Text, str]:
        self._displayed_events = [placeholder_class]
        text = Text()
        text.append(message)
        return text, f"chat-placeholder {placeholder_class}"

    @staticmethod
    def _merge_renderables(renderables: list[Any]) -> Text:
        """Merge renderables into a single Text for mouse text selection support."""
        combined = Text()
        for i, item in enumerate(renderables):
            if i > 0:
                combined.append("\n")
            StrixTUIApp._append_renderable(combined, item)
        return StrixTUIApp._sanitize_text(combined)

    @staticmethod
    def _sanitize_text(text: Text) -> Text:
        """Clamp spans so Rich/Textual can't crash on malformed offsets."""
        plain = text.plain
        text_length = len(plain)
        sanitized_spans: list[Span] = []

        for span in text.spans:
            start = max(0, min(span.start, text_length))
            end = max(0, min(span.end, text_length))
            if end > start:
                sanitized_spans.append(Span(start, end, span.style))

        return Text(
            plain,
            style=text.style,
            justify=text.justify,
            overflow=text.overflow,
            no_wrap=text.no_wrap,
            end=text.end,
            tab_size=text.tab_size,
            spans=sanitized_spans,
        )

    @staticmethod
    def _append_renderable(combined: Text, item: Any) -> None:
        """Recursively append a renderable's text content to a combined Text."""
        if isinstance(item, Text):
            combined.append_text(StrixTUIApp._sanitize_text(item))
        elif isinstance(item, Group):
            for j, sub in enumerate(item.renderables):
                if j > 0:
                    combined.append("\n")
                StrixTUIApp._append_renderable(combined, sub)
        else:
            inner = getattr(item, "content", None) or getattr(item, "renderable", None)
            if inner is not None:
                StrixTUIApp._append_renderable(combined, inner)
            else:
                combined.append(str(item))

    def _get_rendered_events_content(self, events: list[dict[str, Any]]) -> Any:
        renderables: list[Any] = []

        if not events:
            return Text()

        for event in events:
            content: Any = None

            if event["type"] == "chat":
                content = self._render_chat_content(event["data"])
            elif event["type"] == "tool":
                content = render_tool_widget(event["data"])

            if content:
                if renderables:
                    renderables.append(Text(""))
                renderables.append(content)

        if not renderables:
            return Text()

        if len(renderables) == 1 and isinstance(renderables[0], Text):
            return self._sanitize_text(renderables[0])

        return self._merge_renderables(renderables)

    def _get_status_display_content(
        self, agent_id: str, agent_data: dict[str, Any]
    ) -> tuple[Text | None, Text, bool]:
        status = agent_data.get("status", "running")

        def keymap_styled(keys: list[tuple[str, str]]) -> Text:
            t = Text()
            for i, (key, action) in enumerate(keys):
                if i > 0:
                    t.append(" · ", style="dim")
                t.append(key, style="white")
                t.append(" ", style="dim")
                t.append(action, style="dim")
            return t

        simple_statuses: dict[str, tuple[str, str]] = {
            "stopped": ("Agent stopped", ""),
            "completed": ("Agent completed", ""),
        }

        if status in simple_statuses:
            msg, _ = simple_statuses[status]
            metadata = agent_data.get("metadata", {})
            task = metadata.get("task", "")
            task_desc = f" | Task: {task}" if task else ""
            text = Text()
            text.append(f"{msg}{task_desc}")
            return (text, Text(), False)

        if status == "failed":
            error_msg = agent_data.get("error_message", "")
            metadata = agent_data.get("metadata", {})
            task = metadata.get("task", "")
            task_desc = f" | Task: {task}" if task else ""
            text = Text()
            if error_msg:
                text.append(f"{error_msg}{task_desc}", style="red")
            else:
                text.append(f"Scan failed{task_desc}", style="red")
            self._stop_dot_animation()
            return (text, Text(), False)

        if status == "waiting":
            metadata = agent_data.get("metadata", {})
            task = metadata.get("task", "")
            task_desc = f"Waiting | Task: {task}" if task else "Waiting"
            keymap = Text()
            keymap.append("Send message to resume", style="dim")
            return (Text(task_desc), keymap, False)

        if status == "running":
            metadata = agent_data.get("metadata", {})
            task = metadata.get("task", "")
            task_desc = f" : {task}" if task else ""
            if self._agent_has_real_activity(agent_id):
                animated_text = Text()
                animated_text.append_text(self._get_sweep_animation(self._sweep_colors))
                animated_text.append("esc", style="white")
                animated_text.append(" ", style="dim")
                animated_text.append("stop", style="dim")
                if task_desc:
                    animated_text.append(task_desc, style="dim")
                return (animated_text, keymap_styled([("ctrl-q", "quit")]), True)
            animated_text = self._get_animated_verb_text(agent_id, f"Initializing{task_desc}")
            return (animated_text, keymap_styled([("ctrl-q", "quit")]), True)

        return (None, Text(), False)

    def _update_agent_status_display(self) -> None:
        try:
            status_display = self.query_one("#agent_status_display", Horizontal)
            status_text = self.query_one("#status_text", Static)
            keymap_indicator = self.query_one("#keymap_indicator", Static)
        except (ValueError, Exception):
            return

        widgets = [status_display, status_text, keymap_indicator]
        if not all(self._is_widget_safe(w) for w in widgets):
            return

        if not self.selected_agent_id:
            self._safe_widget_operation(status_display.add_class, "hidden")
            return

        try:
            agent_data = self.live_view.agents[self.selected_agent_id]
            content, keymap, should_animate = self._get_status_display_content(
                self.selected_agent_id, agent_data
            )

            if not content:
                self._safe_widget_operation(status_display.add_class, "hidden")
                return

            self._safe_widget_operation(status_text.update, content)
            self._safe_widget_operation(keymap_indicator.update, keymap)
            self._safe_widget_operation(status_display.remove_class, "hidden")

            if should_animate:
                self._start_dot_animation()

        except (KeyError, Exception):
            self._safe_widget_operation(status_display.add_class, "hidden")

    def _update_stats_display(self) -> None:
        try:
            stats_display = self.query_one("#stats_display", Static)
        except (ValueError, Exception):
            return

        if not self._is_widget_safe(stats_display):
            return

        if self.screen.selections:
            return

        stats_content = Text()

        stats_text = build_tui_stats_text(self.report_state)
        if stats_text:
            stats_content.append(stats_text)

        version = get_package_version()
        stats_content.append(f"\nv{version}", style="white")

        if self.selected_agent_id:
            selected_agent = self.live_view.agents.get(self.selected_agent_id)
            if selected_agent:
                stats_content.append("\n\n")
                stats_content.append("── Agent Details ──\n", style="bold #a8a29e")

                name = selected_agent.get("name", "Unknown")
                status = selected_agent.get("status", "running")
                status_colors = {
                    "running": "#60a5fa",
                    "waiting": "#fbbf24",
                    "completed": "#34d399",
                    "failed": "#f87171",
                    "stopped": "#9ca3af",
                }
                status_color = status_colors.get(status, "white")

                stats_content.append("Name: ", style="bold")
                stats_content.append(f"{name}\n", style="white")

                stats_content.append("Status: ", style="bold")
                stats_content.append(f"{status.upper()}\n", style=status_color)

                vuln_count = self._agent_vulnerability_count(self.selected_agent_id)
                if vuln_count > 0:
                    stats_content.append("Vulns: ", style="bold")
                    stats_content.append(f"{vuln_count}\n", style="bold red")

                metadata = selected_agent.get("metadata", {})
                task = metadata.get("task", "")
                if task:
                    stats_content.append("Task: ", style="bold")
                    stats_content.append(f"{task}\n", style="white")

                skills = metadata.get("skills", [])
                if skills:
                    stats_content.append("Skills:\n", style="bold")
                    for skill in skills:
                        stats_content.append(f"  • {skill}\n", style="dim white")

        self._safe_widget_operation(stats_display.update, stats_content)

    def _get_enriched_vulns(self, vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
        enriched_vulns = []
        for vuln in vulnerabilities:
            enriched = dict(vuln)
            agent_name = enriched.get("agent_name")
            agent_id = enriched.get("agent_id")
            if not agent_name and isinstance(agent_id, str):
                agent_name = self._get_agent_name(agent_id)
            if agent_name:
                enriched["agent_name"] = agent_name
            enriched_vulns.append(enriched)
        return enriched_vulns

    def _update_vulnerabilities_panel(self) -> None:
        """Update the vulnerabilities panel with current vulnerability data."""
        try:
            vuln_panel = self.query_one("#vulnerabilities_panel", VulnerabilitiesPanel)
        except (ValueError, Exception):
            return

        if not self._is_widget_safe(vuln_panel):
            return

        vulnerabilities = self.report_state.vulnerability_reports

        if not vulnerabilities:
            self._safe_widget_operation(vuln_panel.add_class, "hidden")
            return

        enriched_vulns = self._get_enriched_vulns(vulnerabilities)
        self._safe_widget_operation(vuln_panel.remove_class, "hidden")
        vuln_panel.update_vulnerabilities(enriched_vulns)

    def _update_vulnerabilities_tab_view(self) -> None:
        """Update the vulnerabilities tab database."""
        vulnerabilities = self.report_state.vulnerability_reports
        enriched_vulns = self._get_enriched_vulns(vulnerabilities)
        self._update_vulnerabilities_tab(enriched_vulns)

    def _update_vulnerabilities_tab(self, enriched_vulns: list[dict[str, Any]]) -> None:
        """Update the vulnerabilities tab list and select first if index is empty."""
        try:
            vuln_list = self.query_one("#vulns_tab_list", ListView)
        except (ValueError, Exception):
            return

        if not self._is_widget_safe(vuln_list):
            return

        current_index = vuln_list.index

        # Avoid clearing and resetting selection if the vulnerability list hasn't changed.
        existing_vulns = [
            item.vuln_data
            for item in vuln_list.children
            if isinstance(item, VulnerabilityReportItem)
        ]
        if existing_vulns == enriched_vulns:
            return

        vuln_list.clear()

        if not enriched_vulns:
            with contextlib.suppress(Exception):
                self.query_one("#vulns_tab_markdown", Markdown).update("")
            return

        for vuln in enriched_vulns:
            severity = vuln.get("severity", "info").lower()
            title = vuln.get("title", "Unknown Vulnerability")
            color = VulnerabilitiesPanel.SEVERITY_COLORS.get(severity, "#3b82f6")

            label = Text()
            label.append("● ", style=Style(color=color))
            label.append(title, style=Style(color="#d4d4d4"))

            item = VulnerabilityReportItem(vuln, label)
            vuln_list.append(item)

        if current_index is not None and current_index < len(enriched_vulns):
            vuln_list.index = current_index
        else:
            vuln_list.index = 0

        if vuln_list.index is not None and vuln_list.index < len(enriched_vulns):
            selected_vuln = enriched_vulns[vuln_list.index]
            md_text = build_vulnerability_markdown(selected_vuln)
            with contextlib.suppress(Exception):
                self.query_one("#vulns_tab_markdown", Markdown).update(md_text)

    def _update_markdown_preview(self, item: ListItem | None) -> None:
        if not item or not isinstance(item, VulnerabilityReportItem):
            return

        md_text = build_vulnerability_markdown(item.vuln_data)
        try:
            markdown_widget = self.query_one("#vulns_tab_markdown", Markdown)
            markdown_widget.update(md_text)
        except Exception:
            logger.exception("Failed to update vulnerability markdown")

    @on(ListView.Highlighted, "#vulns_tab_list")
    def on_vuln_highlighted(self, event: ListView.Highlighted) -> None:
        self._update_markdown_preview(event.item)

    @on(ListView.Selected, "#vulns_tab_list")
    def on_vuln_selected(self, event: ListView.Selected) -> None:
        self._update_markdown_preview(event.item)

    def _get_sweep_animation(self, color_palette: list[str]) -> Text:
        text = Text()
        num_squares = self._sweep_num_squares
        num_colors = len(color_palette)

        offset = num_colors - 1
        max_pos = (num_squares - 1) + offset
        total_range = max_pos + offset
        cycle_length = total_range * 2
        frame_in_cycle = self._spinner_frame_index % cycle_length

        wave_pos = total_range - abs(total_range - frame_in_cycle)
        sweep_pos = wave_pos - offset

        dot_color = "#0a3d1f"

        for i in range(num_squares):
            dist = abs(i - sweep_pos)
            color_idx = max(0, num_colors - 1 - dist)

            if color_idx == 0:
                text.append("·", style=Style(color=dot_color))
            else:
                color = color_palette[color_idx]
                text.append("▪", style=Style(color=color))

        text.append(" ")
        return text

    def _get_animated_verb_text(self, agent_id: str, verb: str) -> Text:  # noqa: ARG002
        text = Text()
        sweep = self._get_sweep_animation(self._sweep_colors)
        text.append_text(sweep)
        parts = verb.split(" ", 1)
        text.append(parts[0], style="white")
        if len(parts) > 1:
            text.append(" ", style="dim")
            text.append(parts[1], style="dim")
        return text

    def _start_dot_animation(self) -> None:
        if self._dot_animation_timer is None:
            self._dot_animation_timer = self.set_interval(0.06, self._animate_dots)

    def _stop_dot_animation(self) -> None:
        if self._dot_animation_timer is not None:
            self._dot_animation_timer.stop()
            self._dot_animation_timer = None

    def _animate_dots(self) -> None:
        has_active_agents = False

        if self.selected_agent_id and self.selected_agent_id in self.live_view.agents:
            agent_data = self.live_view.agents[self.selected_agent_id]
            status = agent_data.get("status", "running")
            if status in ["running", "waiting"]:
                has_active_agents = True
                num_colors = len(self._sweep_colors)
                offset = num_colors - 1
                max_pos = (self._sweep_num_squares - 1) + offset
                total_range = max_pos + offset
                cycle_length = total_range * 2
                self._spinner_frame_index = (self._spinner_frame_index + 1) % cycle_length
                self._update_agent_status_display()

        if not has_active_agents:
            has_active_agents = any(
                agent_data.get("status", "running") in ["running", "waiting"]
                for agent_data in self.live_view.agents.values()
            )

        if not has_active_agents:
            self._stop_dot_animation()
            self._spinner_frame_index = 0

    def _agent_has_real_activity(self, agent_id: str) -> bool:
        return self.live_view.has_events_for_agent(agent_id)

    def _agent_vulnerability_count(self, agent_id: str) -> int:
        return sum(
            1
            for vuln in self.report_state.vulnerability_reports
            if vuln.get("agent_id") == agent_id
        )

    def _gather_agent_events(self, agent_id: str) -> list[dict[str, Any]]:
        events = self.live_view.events_for_agent(agent_id)
        events.sort(key=lambda e: (e["timestamp"], e["id"]))
        return events

    def watch_selected_agent_id(self, _agent_id: str | None) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self._is_mounted:
            return

        self._displayed_events.clear()

        self.call_later(self._update_chat_view)
        self._update_agent_status_display()

    def _start_scan_thread(self) -> None:
        def scan_target() -> None:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self._scan_loop = loop

                try:
                    if not self._scan_stop_event.is_set():
                        image = load_settings().runtime.image or "strix-sandbox:latest"
                        loop.run_until_complete(
                            run_strix_scan(
                                scan_config=self.scan_config,
                                scan_id=self.scan_config["run_name"],
                                image=str(image),
                                local_sources=getattr(self.args, "local_sources", None) or [],
                                coordinator=self.coordinator,
                                interactive=True,
                                event_sink=self._capture_sdk_event,
                            ),
                        )

                except (KeyboardInterrupt, asyncio.CancelledError):
                    logger.info("Scan interrupted by user")
                except (ConnectionError, TimeoutError) as e:
                    logging.exception("Network error during scan")
                    self._scan_error = e
                except RuntimeError as e:
                    logging.exception("Runtime error during scan")
                    self._scan_error = e
                except Exception as e:
                    logging.exception("Unexpected error during scan")
                    self._scan_error = e
                finally:
                    with contextlib.suppress(Exception):
                        loop.run_until_complete(
                            session_manager.cleanup(self.scan_config["run_name"]),
                        )
                    loop.close()
                    self._scan_completed.set()

            except Exception:
                logging.exception("Error setting up scan thread")
                self._scan_completed.set()

        self._scan_thread = threading.Thread(target=scan_target, daemon=True)
        self._scan_thread.start()

    def _capture_sdk_event(self, agent_id: str, event: Any) -> None:
        try:
            self.call_from_thread(self._record_sdk_event, agent_id, event)
        except RuntimeError:
            self._record_sdk_event(agent_id, event)

    def _record_sdk_event(self, agent_id: str, event: Any) -> None:
        self.live_view.ingest_sdk_event(agent_id, event)

    def _add_agent_node(self, agent_data: dict[str, Any]) -> bool:
        if len(self.screen_stack) > 1 or self.show_splash:
            return False

        if not self._is_mounted:
            return False

        agent_id = agent_data["id"]
        parent_id = agent_data.get("parent_id")
        status = agent_data.get("status", "running")

        try:
            agents_tree = self.query_one("#agents_tree", Tree)
        except (ValueError, Exception):
            return False

        agent_name_raw = agent_data.get("name", "Agent")

        status_indicators = {
            "running": "⚪",
            "waiting": "⏸",
            "completed": "🟢",
            "failed": "🔴",
            "stopped": "■",
        }

        status_icon = status_indicators.get(status, "○")
        vuln_count = self._agent_vulnerability_count(agent_id)
        vuln_indicator = f" ({vuln_count})" if vuln_count > 0 else ""

        metadata = agent_data.get("metadata", {})
        task = metadata.get("task", "")
        task_suffix = f" [{task[:20]}...]" if len(task) > 20 else f" [{task}]" if task else ""
        agent_name = f"{status_icon} {agent_name_raw}{vuln_indicator}{task_suffix}"

        try:
            if parent_id and parent_id in self.agent_nodes:
                parent_node = self.agent_nodes[parent_id]
                agent_node = parent_node.add(
                    agent_name,
                    data={"agent_id": agent_id},
                )
                parent_node.allow_expand = True
            else:
                agent_node = agents_tree.root.add(
                    agent_name,
                    data={"agent_id": agent_id},
                )

            agent_node.allow_expand = False
            agent_node.expand()
            self.agent_nodes[agent_id] = agent_node

            if len(self.agent_nodes) == 1:
                agents_tree.select_node(agent_node)
                self.selected_agent_id = agent_id

            self._reorganize_orphaned_agents(agent_id)
            return True
        except (AttributeError, ValueError, RuntimeError) as e:
            logger.warning(f"Failed to add agent node {agent_id}: {e}")
            return False

    def _copy_node_under(self, node_to_copy: TreeNode[Any], new_parent: TreeNode[Any]) -> None:
        if node_to_copy.data is None:
            return
        agent_id = node_to_copy.data["agent_id"]
        agent_data = self.live_view.agents.get(agent_id, {})
        agent_name_raw = agent_data.get("name", "Agent")
        status = agent_data.get("status", "running")

        status_indicators = {
            "running": "⚪",
            "waiting": "⏸",
            "completed": "🟢",
            "failed": "🔴",
            "stopped": "■",
        }

        status_icon = status_indicators.get(status, "○")
        vuln_count = self._agent_vulnerability_count(agent_id)
        vuln_indicator = f" ({vuln_count})" if vuln_count > 0 else ""

        metadata = agent_data.get("metadata", {})
        task = metadata.get("task", "")
        task_suffix = f" [{task[:20]}...]" if len(task) > 20 else f" [{task}]" if task else ""
        agent_name = f"{status_icon} {agent_name_raw}{vuln_indicator}{task_suffix}"

        new_node = new_parent.add(
            agent_name,
            data=node_to_copy.data,
        )
        new_node.allow_expand = node_to_copy.allow_expand

        self.agent_nodes[agent_id] = new_node

        for child in node_to_copy.children:
            self._copy_node_under(child, new_node)

        if node_to_copy.is_expanded:
            new_node.expand()

    def _reorganize_orphaned_agents(self, new_parent_id: str) -> None:
        agents_to_move = []

        for agent_id, agent_data in list(self.live_view.agents.items()):
            if (
                agent_data.get("parent_id") == new_parent_id
                and agent_id in self.agent_nodes
                and agent_id != new_parent_id
            ):
                agents_to_move.append(agent_id)

        if not agents_to_move:
            return

        parent_node = self.agent_nodes[new_parent_id]

        for child_agent_id in agents_to_move:
            if child_agent_id in self.agent_nodes:
                old_node = self.agent_nodes[child_agent_id]

                if old_node.parent is parent_node:
                    continue

                self._copy_node_under(old_node, parent_node)

                old_node.remove()

        parent_node.allow_expand = True
        parent_node.expand()

    def _render_chat_content(self, msg_data: dict[str, Any]) -> Any:
        role = msg_data.get("role")
        content = msg_data.get("content", "")
        metadata = msg_data.get("metadata", {})

        if not content:
            return None

        del metadata
        if role == "user":
            return UserMessageRenderer.render_simple(content)

        return AgentMessageRenderer.render_simple(content)

    @on(Tree.NodeHighlighted)  # type: ignore[misc]
    def handle_tree_highlight(self, event: Tree.NodeHighlighted[Any]) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self._is_mounted:
            return

        node = event.node

        try:
            agents_tree = self.query_one("#agents_tree", Tree)
        except (ValueError, Exception):
            return

        if self.focused == agents_tree and node.data:
            agent_id = node.data.get("agent_id")
            if agent_id:
                self.selected_agent_id = agent_id

    @on(Tree.NodeSelected)  # type: ignore[misc]
    def handle_tree_node_selected(self, event: Tree.NodeSelected[Any]) -> None:
        if len(self.screen_stack) > 1 or self.show_splash:
            return

        if not self._is_mounted:
            return

        node = event.node

        if node.allow_expand:
            if node.is_expanded:
                node.collapse()
            else:
                node.expand()

    def _send_user_message(self, message: str) -> None:
        if not self.selected_agent_id:
            return

        logger.info(
            "TUI: user message -> %s (len=%d)",
            self.selected_agent_id,
            len(message),
        )
        target_agent_id = self.selected_agent_id

        submitted = send_user_message_to_agent(
            coordinator=self.coordinator,
            loop=self._scan_loop,
            live_view=self.live_view,
            target_agent_id=target_agent_id,
            message=message,
        )
        if not submitted:
            self.notify("Scan loop is not ready; message was not sent", severity="warning")
            return

        self._displayed_events.clear()
        self._update_chat_view()

        self.call_after_refresh(self._focus_chat_input)

    def _get_agent_name(self, agent_id: str) -> str:
        try:
            if agent_id in self.live_view.agents:
                agent_name = self.live_view.agents[agent_id].get("name")
                if isinstance(agent_name, str):
                    return agent_name
        except (KeyError, AttributeError) as e:
            logger.warning(f"Could not retrieve agent name for {agent_id}: {e}")
        return "Unknown Agent"

    def action_toggle_help(self) -> None:
        if self.show_splash or not self._is_mounted:
            return

        try:
            self.query_one("#main_container")
        except (ValueError, Exception):
            return

        if isinstance(self.screen, HelpScreen):
            self.pop_screen()
            return

        if len(self.screen_stack) > 1:
            return

        self.push_screen(HelpScreen())

    def action_request_quit(self) -> None:
        if self.show_splash or not self._is_mounted:
            self.action_custom_quit()
            return

        if len(self.screen_stack) > 1:
            return

        try:
            self.query_one("#main_container")
        except (ValueError, Exception):
            self.action_custom_quit()
            return

        self.push_screen(QuitScreen())

    def action_stop_selected_agent(self) -> None:
        if self.show_splash or not self._is_mounted:
            return

        if len(self.screen_stack) > 1:
            self.pop_screen()
            return

        if not self.selected_agent_id:
            return

        agent_name, should_stop = self._validate_agent_for_stopping()
        if not should_stop:
            return

        try:
            self.query_one("#main_container")
        except (ValueError, Exception):
            return

        self.push_screen(StopAgentScreen(agent_name, self.selected_agent_id))

    def _validate_agent_for_stopping(self) -> tuple[str, bool]:
        agent_name = "Unknown Agent"

        try:
            if self.selected_agent_id in self.live_view.agents:
                agent_data = self.live_view.agents[self.selected_agent_id]
                agent_name = agent_data.get("name", "Unknown Agent")

                agent_status = agent_data.get("status", "running")
                if agent_status not in ["running", "waiting"]:
                    return agent_name, False

                agent_events = self._gather_agent_events(self.selected_agent_id)
                if not agent_events:
                    return agent_name, False

                return agent_name, True

        except (KeyError, AttributeError, ValueError) as e:
            logger.warning(f"Failed to gather agent events: {e}")

        return agent_name, False

    def action_confirm_stop_agent(self, agent_id: str) -> None:
        if self._scan_loop is None or self._scan_loop.is_closed():
            logger.warning("No active scan loop; cannot stop agent %s", agent_id)
            return
        logger.info("TUI: graceful stop requested for %s (cascade)", agent_id)
        asyncio.run_coroutine_threadsafe(
            self.coordinator.cancel_descendants_graceful(agent_id),
            self._scan_loop,
        )

    def action_custom_quit(self) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            self._scan_stop_event.set()
            self._scan_thread.join(timeout=1.0)

        # The scan thread is a daemon thread and may be killed before its finally
        # block runs cleanup. Explicitly delete the container here so it is never
        # left dangling after the user closes the TUI.
        scan_loop = self._scan_loop
        if scan_loop is not None and not scan_loop.is_closed():
            import asyncio as _asyncio

            _future = _asyncio.run_coroutine_threadsafe(
                session_manager.cleanup(self.scan_config["run_name"]),
                scan_loop,
            )
            try:
                _future.result(timeout=10.0)
            except Exception:
                logger.debug("Container cleanup on quit raised", exc_info=True)

        self.report_state.cleanup()

        self.exit()

    def _is_widget_safe(self, widget: Any) -> bool:
        try:
            _ = widget.screen
        except (AttributeError, ValueError, Exception):
            return False
        else:
            return bool(widget.is_mounted)

    def _safe_widget_operation(
        self, operation: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> bool:
        try:
            operation(*args, **kwargs)
        except (AttributeError, ValueError, Exception):
            return False
        else:
            return True

    def on_resize(self, event: events.Resize) -> None:
        if self.show_splash or not self._is_mounted:
            return

        try:
            sidebar = self.query_one("#sidebar", Vertical)
            chat_area = self.query_one("#chat_area_container", Vertical)
        except (ValueError, Exception):
            return

        if event.size.width < self.SIDEBAR_MIN_WIDTH:
            sidebar.add_class("-hidden")
            chat_area.add_class("-full-width")
        else:
            sidebar.remove_class("-hidden")
            chat_area.remove_class("-full-width")

    def on_mouse_up(self, _event: events.MouseUp) -> None:
        self.set_timer(0.05, self._auto_copy_selection)

    _ICON_PREFIXES: ClassVar[tuple[str, ...]] = (
        "🐞 ",
        "🌐 ",
        "📋 ",
        "🧠 ",
        "◆ ",
        "◇ ",
        "◈ ",
        "→ ",
        "○ ",
        "● ",
        "✓ ",
        "✗ ",
        "⚠ ",
        "▍ ",
        "▍",
        "┃ ",
        "• ",
        ">_ ",
        "</> ",
        "<~> ",
        "[ ] ",
        "[~] ",
        "[•] ",
    )

    _DECORATIVE_LINES: ClassVar[frozenset[str]] = frozenset(
        {
            "● In progress...",
            "✓ Done",
            "✗ Failed",
            "✗ Error",
            "○ Unknown",
        }
    )

    @staticmethod
    def _clean_copied_text(text: str) -> str:
        lines = text.split("\n")
        cleaned: list[str] = []
        for line in lines:
            stripped = line.lstrip()
            if stripped in StrixTUIApp._DECORATIVE_LINES:
                continue
            if stripped and all(c == "─" for c in stripped):
                continue
            out = line
            for prefix in StrixTUIApp._ICON_PREFIXES:
                if stripped.startswith(prefix):
                    leading = line[: len(line) - len(line.lstrip())]
                    out = leading + stripped[len(prefix) :]
                    break
            cleaned.append(out)
        return "\n".join(cleaned)

    def _auto_copy_selection(self) -> None:
        copied = False

        try:
            if self.screen.selections:
                selected = self.screen.get_selected_text()
                self.screen.clear_selection()
                if selected and selected.strip():
                    cleaned = self._clean_copied_text(selected)
                    self.copy_to_clipboard(cleaned if cleaned.strip() else selected)
                    copied = True
        except Exception:
            logger.debug("Failed to copy screen selection", exc_info=True)

        if not copied:
            try:
                chat_input = self.query_one("#chat_input", ChatTextArea)
                selected = chat_input.selected_text
                if selected and selected.strip():
                    self.copy_to_clipboard(selected)
                    chat_input.move_cursor(chat_input.cursor_location)
                    copied = True
            except Exception:
                logger.debug("Failed to copy chat input selection", exc_info=True)

        if copied:
            self.notify("Copied to clipboard", timeout=2)


async def run_tui(args: argparse.Namespace) -> None:
    app = StrixTUIApp(args)
    await app.run_async()
    if app._scan_error is not None:
        raise app._scan_error
