"""
sec-copilot-cli.src.cli
~~~~~~~~~~~~~~~~~~~~~~~~

CLI entry point — parses arguments, dispatches subcommands, and
orchestrates the interaction between the Gemini client, prompt
registry, and Rich formatter.

Architecture Decision:
    argparse is used for subcommand routing (audit / log / chat) because
    it is stdlib, has zero dependencies, and maps cleanly to the three
    operational modes.  Each subcommand handler is a standalone function
    that follows the Guard-Clause / Early-Return pattern.

Usage:
    python -m src.cli audit  <file>       — Run OWASP static audit
    python -m src.cli log    <file>       — Analyse a log file for IOCs
    python -m src.cli chat                — Interactive sparring session
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src.client import GeminiClient
from src.formatter import (
    console,
    print_banner,
    render_assistant_message,
    render_audit_report,
    render_error,
)


# ──────────────────────────────────────────────────────────────
# Subcommand Handlers
# ──────────────────────────────────────────────────────────────

def _handle_audit(args: argparse.Namespace) -> None:
    """Run OWASP-aligned static-code audit on a source file.

    Guard clauses verify the file exists and is non-empty before
    sending to Gemini.
    """
    filepath = Path(args.file)

    # Guard — file must exist
    if not filepath.is_file():
        render_error(f"File not found: {filepath}")
        sys.exit(1)

    # Guard — file must not be empty
    code = filepath.read_text(encoding="utf-8")
    if not code.strip():
        render_error(f"File is empty: {filepath}")
        sys.exit(1)

    console.print(
        f"[bold cyan]🔍  Auditing:[/bold cyan] {filepath.name}\n"
    )

    client = GeminiClient()
    report = client.generate(
        user_content=f"Audit the following source code:\n\n```\n{code}\n```",
        mode="audit",
    )
    render_audit_report(report)


def _handle_log(args: argparse.Namespace) -> None:
    """Analyse a security-event log file for IOCs and anomalies.

    Guard clauses mirror the audit handler — verify existence and
    non-emptiness.
    """
    filepath = Path(args.file)

    # Guard — file must exist
    if not filepath.is_file():
        render_error(f"Log file not found: {filepath}")
        sys.exit(1)

    # Guard — file must not be empty
    log_data = filepath.read_text(encoding="utf-8")
    if not log_data.strip():
        render_error(f"Log file is empty: {filepath}")
        sys.exit(1)

    console.print(
        f"[bold cyan]📋  Analysing log:[/bold cyan] {filepath.name}\n"
    )

    client = GeminiClient()
    analysis = client.generate(
        user_content=(
            "Analyse the following security event log for IOCs, anomalies, "
            "and potential attack timelines:\n\n"
            f"```\n{log_data}\n```"
        ),
        mode="log",
    )
    render_audit_report(analysis)


def _handle_chat(_args: argparse.Namespace) -> None:
    """Launch an interactive defensive sparring session with multi-turn memory.

    Runs a stateful REPL loop where the Gemini client retains context across turns.
    Type 'exit' or 'quit' to terminate.
    """
    print_banner()
    console.print(
        "[dim]Type your question and press Enter.  "
        "Type [bold]exit[/bold] or [bold]quit[/bold] to end.\n[/dim]"
    )

    client = GeminiClient()
    # Initialise the stateful multi-turn session with the sparring prompt
    client.start_chat(mode="chat")

    while True:
        try:
            user_input = console.input("[bold green]you ❯ [/bold green]")
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Session ended.[/dim]")
            break

        # Guard Clause: Exit commands
        if user_input.strip().lower() in {"exit", "quit", "q"}:
            console.print("[dim]Session ended. Stay safe! 🔐[/dim]")
            break

        # Guard Clause: Empty input
        if not user_input.strip():
            continue

        try:
            # Send message through the stateful session (memory retained)
            response = client.send_chat_message(user_input)
            render_assistant_message(response)
        except Exception as exc:  # noqa: BLE001
            render_error(str(exc))


# ──────────────────────────────────────────────────────────────
# Argument Parser Construction
# ──────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="sec-copilot-cli",
        description=(
            "Defensive AI sparring partner and static code/log auditor.  "
            "Powered by Google Gemini with tuned SafetySettings."
        ),
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        help="Available subcommands",
    )

    # --- audit subcommand ---
    audit_parser = subparsers.add_parser(
        "audit",
        help="Run an OWASP-aligned static security audit on a source file.",
    )
    audit_parser.add_argument(
        "file",
        help="Path to the source file to audit.",
    )
    audit_parser.set_defaults(handler=_handle_audit)

    # --- log subcommand ---
    log_parser = subparsers.add_parser(
        "log",
        help="Analyse a security event log for IOCs and anomalies.",
    )
    log_parser.add_argument(
        "file",
        help="Path to the log file to analyse.",
    )
    log_parser.set_defaults(handler=_handle_log)

    # --- chat subcommand ---
    chat_parser = subparsers.add_parser(
        "chat",
        help="Start an interactive defensive sparring session.",
    )
    chat_parser.set_defaults(handler=_handle_chat)

    return parser


# ──────────────────────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────────────────────

def main() -> None:
    """Parse CLI arguments and dispatch to the appropriate handler."""
    parser = build_parser()
    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
