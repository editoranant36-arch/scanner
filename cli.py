#!/usr/bin/env python3
import sys
import os
import argparse
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import print as rprint

from core.orchestrator import ScannerOrchestrator
from core.models import DecisionStatus

console = Console()

def print_header():
    console.print(Panel.fit(
        "[bold cyan]APPLICATION LEFTOVER FOLDER SCANNER[/bold cyan]\n"
        "[dim]Architecture: Scan Engine • Correlation & Analysis • Decision Engine • Action Layer • Data Layer[/dim]",
        border_style="cyan"
    ))

def display_summary(summary):
    table = Table(title="Scan Overview", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="dim")
    table.add_column("Value", justify="right", style="bold")

    table.add_row("Total Folders Scanned", str(summary.total_folders_scanned))
    table.add_row("Installed Apps Detected", str(summary.installed_apps_count))
    table.add_row("Leftover Folders Found", f"[red]{summary.leftovers_detected}[/red]")
    table.add_row("Active Applications", f"[green]{summary.active_apps_count}[/green]")
    table.add_row("System Protected Folders", f"[yellow]{summary.system_protected_count}[/yellow]")
    table.add_row("Unknown / Uncertain", f"[blue]{summary.uncertain_count}[/blue]")
    rec_mb = summary.total_space_recoverable_bytes / (1024 * 1024)
    table.add_row("Recoverable Disk Space", f"[bold green]{rec_mb:.1f} MB[/bold green]")
    table.add_row("Scan Duration", f"{summary.duration_seconds:.2f} s")

    console.print(table)

def display_items(items, filter_status: Optional[str] = None):
    table = Table(title="Scanned Folders & Classification", show_header=True, header_style="bold blue")
    table.add_column("Status", width=22)
    table.add_column("Folder Name / Path", style="dim")
    table.add_column("Associated App", style="cyan")
    table.add_column("Size", justify="right")
    table.add_column("Analysis / Reason", style="italic")

    for item in items:
        status_val = item.decision.value
        if filter_status and filter_status.lower() not in status_val.lower():
            continue

        if item.decision == DecisionStatus.APPLICATION_DELETED:
            status_style = "[bold white on red] APPLICATION DELETED [/]"
        elif item.decision == DecisionStatus.APPLICATION_EXISTS:
            status_style = "[bold white on green] APPLICATION EXISTS [/]"
        elif item.decision == DecisionStatus.SYSTEM_PROTECTED:
            status_style = "[bold black on yellow] SYSTEM PROTECTED [/]"
        else:
            status_style = "[bold white on blue] UNKNOWN/UNCERTAIN [/]"

        table.add_row(
            status_style,
            f"{item.name}\n[dim]{item.path}[/dim]",
            item.associated_app_name or "-",
            item.size_formatted,
            item.decision_reason
        )

    console.print(table)

def run_interactive_prompts(orchestrator, leftovers):
    if not leftovers:
        console.print("[green]No leftover folders to review![/green]")
        return

    console.print(f"\n[bold yellow]Starting Interactive Review of {len(leftovers)} Leftover Folders...[/bold yellow]\n")

    for idx, item in enumerate(leftovers, 1):
        prompt_panel = Panel(
            f"[bold red]⚠️  Leftover Application Folder Detected ({idx}/{len(leftovers)})[/bold red]\n\n"
            f"[bold]Application:[/bold] {item.associated_app_name or 'Unknown'}\n"
            f"[bold]Status:[/bold] [red]Application is not installed[/red]\n"
            f"[bold]Leftover folder:[/bold] {item.path}\n"
            f"[bold]Size:[/bold] {item.size_formatted}\n\n"
            f"[italic]This folder appears to belong to an application that is no longer installed.[/italic]\n"
            f"What would you like to do?",
            title="[bold]Example User Prompt (Layer 4/5)[/bold]",
            border_style="red"
        )
        console.print(prompt_panel)

        console.print("[1] [red]Delete Folder[/red] (Move to Quarantine)")
        console.print("[2] [green]Keep / Allow[/green] (Add to Allowlist)")
        console.print("[3] [blue]View Folder[/blue] (Inspect contents)")
        console.print("[4] [dim]Ignore[/dim] (Skip this scan)")
        console.print("[5] Exit review")

        choice = Prompt.ask("Choose action", choices=["1", "2", "3", "4", "5"], default="1")

        if choice == "1":
            res = orchestrator.execute_item_action(item.path, "delete", app_name=item.associated_app_name or "")
            if res.get("success"):
                console.print(f"[bold green]✓ {res.get('message')}[/bold green]\n")
            else:
                console.print(f"[bold red]✗ {res.get('error')}[/bold red]\n")
        elif choice == "2":
            res = orchestrator.execute_item_action(item.path, "keep", app_name=item.associated_app_name or "")
            console.print(f"[bold green]✓ {res.get('message')}[/bold green]\n")
        elif choice == "3":
            res = orchestrator.execute_item_action(item.path, "view")
            details = res.get("details", {})
            console.print(f"[bold blue]Folder Details:[/bold blue] {details.get('file_count', 0)} files, {details.get('folder_count', 0)} subdirs")
            if details.get("sample_files"):
                console.print("Sample files:\n  - " + "\n  - ".join(details["sample_files"][:5]))
            console.print()
        elif choice == "4":
            orchestrator.execute_item_action(item.path, "ignore")
            console.print("[dim]Skipped.[/dim]\n")
        elif choice == "5":
            console.print("[yellow]Exiting review.[/yellow]")
            break

def main():
    parser = argparse.ArgumentParser(description="Application Leftover Folder Scanner CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Scan command
    scan_p = subparsers.add_parser("scan", help="Run scanner")
    scan_p.add_argument("--demo", action="store_true", help="Use architecture demo simulation data")
    scan_p.add_argument("--interactive", "-i", action="store_true", help="Prompt for each leftover item")
    scan_p.add_argument("--filter", choices=["deleted", "exists", "protected", "unknown"], help="Filter displayed rows")
    scan_p.add_argument("--custom-path", action="append", help="Custom root path to scan")

    # Quarantine command
    quar_p = subparsers.add_parser("quarantine", help="Manage quarantine")
    quar_p.add_argument("--list", action="store_true", default=True, help="List quarantined folders")
    quar_p.add_argument("--restore", help="Restore item by ID")
    quar_p.add_argument("--delete-perm", help="Permanently delete item by ID")

    # Allowlist command
    allow_p = subparsers.add_parser("allowlist", help="Manage allowlist")
    allow_p.add_argument("--list", action="store_true", default=True, help="List allowlist")
    allow_p.add_argument("--add", help="Add path to allowlist")
    allow_p.add_argument("--remove", help="Remove path from allowlist")

    # History command
    subparsers.add_parser("history", help="View scan history")

    args = parser.parse_args()

    print_header()
    demo = getattr(args, "demo", False)
    orch = ScannerOrchestrator(demo_mode=demo)

    if args.command == "scan" or args.command is None:
        console.print(f"[bold cyan]Scanning file system and applications (Demo Mode: {demo})...[/bold cyan]")
        summary = orch.run_full_scan(custom_paths=getattr(args, "custom_path", None))
        display_summary(summary)
        display_items(summary.items, filter_status=getattr(args, "filter", None))

        leftovers = [i for i in summary.items if i.decision == DecisionStatus.APPLICATION_DELETED]
        if getattr(args, "interactive", False) and leftovers:
            run_interactive_prompts(orch, leftovers)

    elif args.command == "quarantine":
        if args.restore:
            ok = orch.restore_quarantine(args.restore)
            console.print(f"[bold green]Restored successfully: {ok}[/bold green]" if ok else "[bold red]Restore failed[/bold red]")
        elif args.delete_perm:
            ok = orch.delete_quarantine_permanent(args.delete_perm)
            console.print(f"[bold green]Permanently deleted: {ok}[/bold green]" if ok else "[bold red]Delete failed[/bold red]")
        else:
            items = orch.get_quarantine()
            table = Table(title="Quarantine Repository", show_header=True)
            table.add_column("ID")
            table.add_column("Original Path")
            table.add_column("App Name")
            table.add_column("Size")
            table.add_column("Timestamp")
            for it in items:
                table.add_row(it["id"], it["original_path"], it.get("associated_app", "-"), it["size_formatted"], it["timestamp"])
            console.print(table)

    elif args.command == "allowlist":
        if args.add:
            orch.add_allowlist(args.add)
            console.print(f"[green]Added to allowlist: {args.add}[/green]")
        elif args.remove:
            orch.remove_allowlist(args.remove)
            console.print(f"[yellow]Removed from allowlist: {args.remove}[/yellow]")
        else:
            paths = orch.get_allowlist()
            console.print("[bold]Current Allowlist Folders:[/bold]")
            if not paths:
                console.print("[dim]Allowlist is empty.[/dim]")
            for p in paths:
                console.print(f"  • {p}")

    elif args.command == "history":
        history = orch.get_history()
        table = Table(title="Scan History", show_header=True)
        table.add_column("Date / Time")
        table.add_column("Scanned")
        table.add_column("Leftovers")
        table.add_column("Active Apps")
        table.add_column("Protected")
        table.add_column("Space Recoverable")
        for h in history:
            table.add_row(
                h.get("timestamp", "-"),
                str(h.get("total_folders_scanned", 0)),
                str(h.get("leftovers_detected", 0)),
                str(h.get("active_apps_count", 0)),
                str(h.get("system_protected_count", 0)),
                h.get("total_space_recoverable", "0 B")
            )
        console.print(table)

if __name__ == "__main__":
    main()
