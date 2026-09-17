"""
sec-copilot-cli.src.formatter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Rich-based terminal output rendering for audit reports, log analysis
summaries, and interactive chat sessions.

Architecture Decision:
    All presentation logic is centralised here so that cli.py and
    client.py remain free of display concerns (Separation of Concerns).
    Every public function accepts plain data and renders it — no side
    effects beyond writing to the console.
"""

from __future__ import annotations

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text


# Module-level console instance — shared across all rendering helpers.
console = Console()


# ──────────────────────────────────────────────────────────────
# Audit Report Card
# ──────────────────────────────────────────────────────────────

def render_audit_report(report_text: str) -> None:
    """Render a full audit report inside a Rich panel with Markdown.

    Args:
        report_text: The raw Markdown string returned by the auditor
                     persona.
    """
    # Guard clause — empty report
    if not report_text or not report_text.strip():
        console.print(
            "[bold yellow]⚠  No audit findings to display.[/bold yellow]"
        )
        return

    panel = Panel(
        Markdown(report_text),
        title="[bold red]🛡  Security Audit Report[/bold red]",
        border_style="bright_red",
        padding=(1, 2),
    )
    console.print(panel)


# ──────────────────────────────────────────────────────────────
# Code Syntax Display
# ──────────────────────────────────────────────────────────────

def render_code(code: str, language: str = "python", title: str = "Source") -> None:
    """Pretty-print a code block with syntax highlighting.

    Args:
        code:     Source code string.
        language: Pygments lexer name (e.g. 'python', 'javascript').
        title:    Panel title displayed above the code block.
    """
    # Guard clause — empty code
    if not code or not code.strip():
        console.print("[dim]  (empty code block)[/dim]")
        return

    syntax = Syntax(
        code,
        lexer=language,
        theme="monokai",
        line_numbers=True,
        word_wrap=True,
    )
    panel = Panel(syntax, title=f"[bold cyan]{title}[/bold cyan]", border_style="cyan")
    console.print(panel)


# ──────────────────────────────────────────────────────────────
# Findings Summary Table
# ──────────────────────────────────────────────────────────────

# Severity → Rich colour mapping for visual priority in the terminal.
_SEVERITY_COLOURS: dict[str, str] = {
    "CRITICAL": "bold white on red",
    "HIGH":     "bold red",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold blue",
    "INFO":     "dim white",
}


def render_findings_table(
    findings: list[dict[str, str]],
) -> None:
    """Display a tabular summary of audit findings.

    Args:
        findings: List of dicts, each with keys:
                  ``severity``, ``title``, ``owasp_category``.
    """
    # Guard clause — no findings
    if not findings:
        console.print(
            "[bold green]✅  No vulnerabilities detected.[/bold green]"
        )
        return

    table = Table(
        title="Findings Summary",
        show_lines=True,
        header_style="bold magenta",
    )
    table.add_column("#",              justify="right", width=4)
    table.add_column("Severity",       justify="center", width=10)
    table.add_column("Title",          min_width=30)
    table.add_column("OWASP Category", min_width=20)

    for idx, finding in enumerate(findings, start=1):
        severity = finding.get("severity", "INFO").upper()
        style = _SEVERITY_COLOURS.get(severity, "")
        table.add_row(
            str(idx),
            Text(severity, style=style),
            finding.get("title", "—"),
            finding.get("owasp_category", "—"),
        )

    console.print(table)


# ──────────────────────────────────────────────────────────────
# Chat / Interactive Session Helpers
# ──────────────────────────────────────────────────────────────

def render_assistant_message(text: str) -> None:
    """Render an assistant response inside a styled panel.

    Args:
        text: The raw response text (Markdown supported).
    """
    # Guard clause — empty response
    if not text or not text.strip():
        console.print("[dim]  (no response)[/dim]")
        return

    panel = Panel(
        Markdown(text),
        title="[bold green]🤖  sec-copilot[/bold green]",
        border_style="green",
        padding=(1, 2),
    )
    console.print(panel)


def render_error(message: str) -> None:
    """Render an error message with a prominent red panel.

    Args:
        message: Human-readable error description.
    """
    panel = Panel(
        f"[bold red]{message}[/bold red]",
        title="[bold red]❌  Error[/bold red]",
        border_style="red",
    )
    console.print(panel)


def print_banner() -> None:
    """Print the sec-copilot-cli startup banner."""
    banner = Text()
    banner.append("  sec-copilot-cli ", style="bold bright_green")
    banner.append("v0.1.0", style="dim")
    banner.append("  —  Defensive AI Sparring Partner\n", style="italic")
    console.print(
        Panel(banner, border_style="bright_green", padding=(0, 1))
    )
