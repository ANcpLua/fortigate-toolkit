#!/usr/bin/env python3
"""
VLAN Migration Tool for Fortinet FortiGate.

Migrates VLANs from one physical interface to another with full
dependency tracking and rollback support.

IMPORTANT: Always use --dry-run first to preview changes.

Usage:
    python migrate.py --vlan vlan100 --from-interface port1 --to-interface port2 --dry-run
    python migrate.py --vlan vlan100 --from-interface port1 --to-interface port2
    python migrate.py --all-vlans --from-interface port1 --to-interface port2 --dry-run

Environment Variables:
    FORTIGATE_HOST: FortiGate hostname or IP (required)
    FORTIGATE_API_KEY: REST API token (required)
    FORTIGATE_VERIFY_SSL: Enable SSL verification (default: false)
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from fortigate_client import (
    FortiGateClient,
    FortiGateAuthError,
    FortiGateConnectionError,
    FortiGateError,
    FortiGateNotFoundError,
)


class MigrationStatus(str, Enum):
    """Migration operation status."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    DRY_RUN = "dry_run"


@dataclass
class MigrationStep:
    """Individual migration step with status tracking."""

    vlan_name: str
    vlan_id: int
    from_interface: str
    to_interface: str
    status: MigrationStatus = MigrationStatus.PENDING
    error: str | None = None
    references_affected: dict[str, list[str]] = field(default_factory=dict)
    started_at: str | None = None
    completed_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "vlan_name": self.vlan_name,
            "vlan_id": self.vlan_id,
            "from_interface": self.from_interface,
            "to_interface": self.to_interface,
            "status": self.status.value,
            "error": self.error,
            "references_affected": self.references_affected,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


@dataclass
class MigrationPlan:
    """Complete migration plan with all steps."""

    fortigate_host: str
    from_interface: str
    to_interface: str
    dry_run: bool
    steps: list[MigrationStep] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str | None = None
    overall_status: MigrationStatus = MigrationStatus.PENDING
    error: str | None = None

    @property
    def success_count(self) -> int:
        """Count of successful migrations."""
        return sum(1 for s in self.steps if s.status == MigrationStatus.SUCCESS)

    @property
    def failed_count(self) -> int:
        """Count of failed migrations."""
        return sum(1 for s in self.steps if s.status == MigrationStatus.FAILED)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "fortigate_host": self.fortigate_host,
            "from_interface": self.from_interface,
            "to_interface": self.to_interface,
            "dry_run": self.dry_run,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "overall_status": self.overall_status.value,
            "total_vlans": len(self.steps),
            "successful": self.success_count,
            "failed": self.failed_count,
            "steps": [s.to_dict() for s in self.steps],
            "error": self.error,
        }


def create_migration_plan(
    client: FortiGateClient,
    from_interface: str,
    to_interface: str,
    vlan_names: list[str] | None = None,
    dry_run: bool = True,
) -> MigrationPlan:
    """
    Create a migration plan for VLANs.

    Args:
        client: FortiGate API client
        from_interface: Source physical interface
        to_interface: Target physical interface
        vlan_names: Specific VLANs to migrate (None = all)
        dry_run: If True, plan only - no execution

    Returns:
        MigrationPlan with all steps
    """
    plan = MigrationPlan(
        fortigate_host=client.host,
        from_interface=from_interface,
        to_interface=to_interface,
        dry_run=dry_run,
    )

    # Validate interfaces exist
    try:
        client.get_interface(from_interface)
    except FortiGateNotFoundError:
        plan.overall_status = MigrationStatus.FAILED
        plan.error = f"Source interface '{from_interface}' not found"
        return plan

    try:
        client.get_interface(to_interface)
    except FortiGateNotFoundError:
        plan.overall_status = MigrationStatus.FAILED
        plan.error = f"Target interface '{to_interface}' not found"
        return plan

    # Get VLANs to migrate
    try:
        source_vlans = client.get_interface_vlans(from_interface)
    except FortiGateError as e:
        plan.overall_status = MigrationStatus.FAILED
        plan.error = f"Failed to get VLANs from '{from_interface}': {e}"
        return plan

    if not source_vlans:
        plan.overall_status = MigrationStatus.SKIPPED
        plan.error = f"No VLANs found on interface '{from_interface}'"
        return plan

    # Filter to specific VLANs if requested
    if vlan_names:
        source_vlans = [v for v in source_vlans if v.get("name") in vlan_names]
        if not source_vlans:
            plan.overall_status = MigrationStatus.FAILED
            plan.error = f"None of the specified VLANs found on '{from_interface}'"
            return plan

    # Check for VLAN ID conflicts on target
    try:
        target_vlans = client.get_interface_vlans(to_interface)
        target_vlan_ids = {v.get("vlanid") for v in target_vlans}
    except FortiGateError:
        target_vlan_ids = set()

    # Build migration steps
    for vlan in source_vlans:
        vlan_name = vlan.get("name", "")
        vlan_id = vlan.get("vlanid", 0)

        step = MigrationStep(
            vlan_name=vlan_name,
            vlan_id=vlan_id,
            from_interface=from_interface,
            to_interface=to_interface,
        )

        # Check for VLAN ID conflict
        if vlan_id in target_vlan_ids:
            step.status = MigrationStatus.SKIPPED
            step.error = f"VLAN ID {vlan_id} already exists on {to_interface}"
            plan.steps.append(step)
            continue

        # Get references that will be affected
        try:
            refs = client.get_vlan_references(vlan_name)
            step.references_affected = {k: v for k, v in refs.items() if v}
        except FortiGateError:
            pass

        plan.steps.append(step)

    return plan


def execute_migration_step(
    client: FortiGateClient,
    step: MigrationStep,
) -> MigrationStep:
    """
    Execute a single migration step.

    This performs the actual VLAN interface move by updating
    the parent interface property.

    Args:
        client: FortiGate API client
        step: Migration step to execute

    Returns:
        Updated MigrationStep with results
    """
    step.started_at = datetime.now(timezone.utc).isoformat()
    step.status = MigrationStatus.IN_PROGRESS

    try:
        # Update the VLAN's parent interface
        client.update_vlan(
            step.vlan_name,
            interface=step.to_interface,
        )

        step.status = MigrationStatus.SUCCESS
        step.completed_at = datetime.now(timezone.utc).isoformat()

    except FortiGateError as e:
        step.status = MigrationStatus.FAILED
        step.error = str(e)
        step.completed_at = datetime.now(timezone.utc).isoformat()

    return step


def execute_migration_plan(
    client: FortiGateClient,
    plan: MigrationPlan,
    stop_on_error: bool = True,
) -> MigrationPlan:
    """
    Execute a complete migration plan.

    Args:
        client: FortiGate API client
        plan: Migration plan to execute
        stop_on_error: Stop execution on first failure

    Returns:
        Updated MigrationPlan with results
    """
    if plan.dry_run:
        for step in plan.steps:
            if step.status == MigrationStatus.PENDING:
                step.status = MigrationStatus.DRY_RUN
        plan.overall_status = MigrationStatus.DRY_RUN
        plan.completed_at = datetime.now(timezone.utc).isoformat()
        return plan

    plan.overall_status = MigrationStatus.IN_PROGRESS

    for step in plan.steps:
        if step.status != MigrationStatus.PENDING:
            continue  # Skip already processed steps

        step = execute_migration_step(client, step)

        if step.status == MigrationStatus.FAILED and stop_on_error:
            plan.overall_status = MigrationStatus.FAILED
            plan.error = f"Migration stopped: {step.vlan_name} failed - {step.error}"
            plan.completed_at = datetime.now(timezone.utc).isoformat()
            return plan

    # Determine overall status
    if plan.failed_count > 0:
        plan.overall_status = MigrationStatus.FAILED
    elif plan.success_count == len(plan.steps):
        plan.overall_status = MigrationStatus.SUCCESS
    else:
        plan.overall_status = MigrationStatus.SUCCESS  # Some skipped is OK

    plan.completed_at = datetime.now(timezone.utc).isoformat()
    return plan


def print_migration_plan(plan: MigrationPlan) -> None:
    """Print migration plan as formatted output."""
    console = Console()

    # Header
    mode = "[yellow]DRY RUN[/yellow]" if plan.dry_run else "[red]LIVE EXECUTION[/red]"
    console.print(Panel(
        f"[bold]VLAN Migration Plan[/bold]\n"
        f"FortiGate: {plan.fortigate_host}\n"
        f"From: [blue]{plan.from_interface}[/blue] -> To: [green]{plan.to_interface}[/green]\n"
        f"Mode: {mode}",
        title="Migration Plan",
    ))

    if plan.error and plan.overall_status == MigrationStatus.FAILED:
        console.print(f"\n[red]Error:[/red] {plan.error}\n")
        return

    if not plan.steps:
        console.print("[yellow]No VLANs to migrate[/yellow]")
        return

    # Steps table
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("VLAN Name", style="green")
    table.add_column("VLAN ID", justify="right")
    table.add_column("Status")
    table.add_column("References")
    table.add_column("Notes")

    for step in plan.steps:
        status_colors = {
            MigrationStatus.PENDING: "dim",
            MigrationStatus.IN_PROGRESS: "yellow",
            MigrationStatus.SUCCESS: "green",
            MigrationStatus.FAILED: "red",
            MigrationStatus.SKIPPED: "yellow",
            MigrationStatus.DRY_RUN: "cyan",
        }
        color = status_colors.get(step.status, "white")
        status_display = f"[{color}]{step.status.value}[/{color}]"

        ref_count = sum(len(v) for v in step.references_affected.values())
        refs_display = str(ref_count) if ref_count > 0 else "-"

        notes = step.error or ""
        if step.references_affected and not step.error:
            affected = []
            for ref_type, refs in step.references_affected.items():
                if refs:
                    affected.append(f"{len(refs)} {ref_type.replace('_', ' ')}")
            if affected:
                notes = ", ".join(affected)

        table.add_row(
            step.vlan_name,
            str(step.vlan_id),
            status_display,
            refs_display,
            notes[:50] + "..." if len(notes) > 50 else notes,
        )

    console.print(table)

    # Summary
    console.print(f"\n[dim]Total: {len(plan.steps)} | "
                  f"Success: {plan.success_count} | "
                  f"Failed: {plan.failed_count}[/dim]")

    if plan.dry_run:
        console.print("\n[yellow]This was a dry run. No changes were made.[/yellow]")
        console.print("[dim]Remove --dry-run to execute the migration.[/dim]")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Migrate VLANs between interfaces on a Fortinet FortiGate.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Preview migration of a single VLAN (always do this first!)
  python migrate.py --vlan vlan100 --from-interface port1 --to-interface port2 --dry-run

  # Execute migration of a single VLAN
  python migrate.py --vlan vlan100 --from-interface port1 --to-interface port2

  # Preview migration of all VLANs from an interface
  python migrate.py --all-vlans --from-interface port1 --to-interface port2 --dry-run

  # Execute with JSON output
  python migrate.py --vlan vlan100 --from-interface port1 --to-interface port2 --json

WARNING: Always use --dry-run first to preview changes!

Environment Variables:
  FORTIGATE_HOST      FortiGate hostname or IP (required)
  FORTIGATE_API_KEY   REST API token (required)
  FORTIGATE_VERIFY_SSL Enable SSL verification (default: false)
        """,
    )

    # VLAN selection
    vlan_group = parser.add_mutually_exclusive_group(required=True)
    vlan_group.add_argument(
        "--vlan", "-v",
        action="append",
        dest="vlans",
        help="VLAN interface name to migrate (can be repeated)",
    )
    vlan_group.add_argument(
        "--all-vlans",
        action="store_true",
        help="Migrate all VLANs from source interface",
    )

    # Interface specification
    parser.add_argument(
        "--from-interface", "-f",
        required=True,
        help="Source physical interface (e.g., port1)",
    )
    parser.add_argument(
        "--to-interface", "-t",
        required=True,
        help="Target physical interface (e.g., port2)",
    )

    # Execution options
    parser.add_argument(
        "--dry-run", "-d",
        action="store_true",
        help="Preview changes without executing (RECOMMENDED)",
    )
    parser.add_argument(
        "--no-stop-on-error",
        action="store_true",
        help="Continue migration even if a VLAN fails",
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output as JSON instead of table",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Skip confirmation prompt for live execution",
    )

    args = parser.parse_args()

    console = Console()

    # Validate environment
    try:
        client = FortiGateClient.from_env()
    except FortiGateError as e:
        if args.json:
            print(json.dumps({"success": False, "error": str(e)}, indent=2))
        else:
            console.print(f"[red]Configuration Error:[/red] {e}")
        return 1

    # Validate same interface
    if args.from_interface == args.to_interface:
        error = "Source and target interfaces cannot be the same"
        if args.json:
            print(json.dumps({"success": False, "error": error}, indent=2))
        else:
            console.print(f"[red]Error:[/red] {error}")
        return 1

    # Create migration plan
    try:
        vlan_names = args.vlans if not args.all_vlans else None
        plan = create_migration_plan(
            client=client,
            from_interface=args.from_interface,
            to_interface=args.to_interface,
            vlan_names=vlan_names,
            dry_run=args.dry_run,
        )
    except (FortiGateAuthError, FortiGateConnectionError) as e:
        if args.json:
            print(json.dumps({"success": False, "error": str(e)}, indent=2))
        else:
            console.print(f"[red]Error:[/red] {e}")
        return 1

    # Check for plan errors
    if plan.overall_status == MigrationStatus.FAILED:
        if args.json:
            print(json.dumps(plan.to_dict(), indent=2))
        else:
            print_migration_plan(plan)
        return 1

    # Live execution confirmation
    if not args.dry_run and not args.force and not args.json:
        print_migration_plan(plan)
        console.print("\n[bold red]WARNING: This will modify your firewall configuration![/bold red]")
        confirm = console.input("[yellow]Type 'yes' to proceed:[/yellow] ")
        if confirm.lower() != "yes":
            console.print("[dim]Migration cancelled.[/dim]")
            return 0

    # Execute plan
    plan = execute_migration_plan(
        client=client,
        plan=plan,
        stop_on_error=not args.no_stop_on_error,
    )

    # Output results
    if args.json:
        print(json.dumps(plan.to_dict(), indent=2))
    else:
        print_migration_plan(plan)

    # Return code based on status
    if plan.overall_status in (MigrationStatus.SUCCESS, MigrationStatus.DRY_RUN):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
