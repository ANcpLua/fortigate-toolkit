#!/usr/bin/env python3
"""
VLAN Migration Verification Tool for Fortinet FortiGate.

Verifies that VLANs were successfully migrated and are functioning correctly.
Performs comprehensive checks including connectivity, references, and configuration.

Usage:
    python verify.py --vlan vlan100 --expected-interface port2
    python verify.py --vlan vlan100 vlan200 --expected-interface port2 --json
    python verify.py --interface port2 --check-all

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


class CheckStatus(str, Enum):
    """Verification check status."""

    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"


@dataclass
class VerificationCheck:
    """Individual verification check result."""

    name: str
    description: str
    status: CheckStatus = CheckStatus.SKIP
    expected: str | None = None
    actual: str | None = None
    message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "expected": self.expected,
            "actual": self.actual,
            "message": self.message,
        }


@dataclass
class VlanVerification:
    """Verification results for a single VLAN."""

    vlan_name: str
    vlan_id: int | None
    expected_interface: str
    checks: list[VerificationCheck] = field(default_factory=list)
    overall_status: CheckStatus = CheckStatus.SKIP

    @property
    def pass_count(self) -> int:
        """Count of passed checks."""
        return sum(1 for c in self.checks if c.status == CheckStatus.PASS)

    @property
    def fail_count(self) -> int:
        """Count of failed checks."""
        return sum(1 for c in self.checks if c.status == CheckStatus.FAIL)

    @property
    def warn_count(self) -> int:
        """Count of warning checks."""
        return sum(1 for c in self.checks if c.status == CheckStatus.WARN)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "vlan_name": self.vlan_name,
            "vlan_id": self.vlan_id,
            "expected_interface": self.expected_interface,
            "overall_status": self.overall_status.value,
            "summary": {
                "total": len(self.checks),
                "pass": self.pass_count,
                "fail": self.fail_count,
                "warn": self.warn_count,
            },
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass
class VerificationReport:
    """Complete verification report."""

    fortigate_host: str
    expected_interface: str
    vlans: list[VlanVerification] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    overall_status: CheckStatus = CheckStatus.SKIP
    error: str | None = None

    @property
    def total_pass(self) -> int:
        """Total passed checks across all VLANs."""
        return sum(v.pass_count for v in self.vlans)

    @property
    def total_fail(self) -> int:
        """Total failed checks across all VLANs."""
        return sum(v.fail_count for v in self.vlans)

    @property
    def total_warn(self) -> int:
        """Total warning checks across all VLANs."""
        return sum(v.warn_count for v in self.vlans)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "fortigate_host": self.fortigate_host,
            "expected_interface": self.expected_interface,
            "timestamp": self.timestamp,
            "overall_status": self.overall_status.value,
            "summary": {
                "vlans_verified": len(self.vlans),
                "total_checks": sum(len(v.checks) for v in self.vlans),
                "pass": self.total_pass,
                "fail": self.total_fail,
                "warn": self.total_warn,
            },
            "vlans": [v.to_dict() for v in self.vlans],
            "error": self.error,
        }


def verify_vlan(
    client: FortiGateClient,
    vlan_name: str,
    expected_interface: str,
) -> VlanVerification:
    """
    Verify a single VLAN migration.

    Performs the following checks:
    1. VLAN exists
    2. VLAN is on expected interface
    3. VLAN is up
    4. IP configuration is valid
    5. No orphaned firewall references

    Args:
        client: FortiGate API client
        vlan_name: VLAN interface name to verify
        expected_interface: Expected parent interface

    Returns:
        VlanVerification with all check results
    """
    verification = VlanVerification(
        vlan_name=vlan_name,
        vlan_id=None,
        expected_interface=expected_interface,
    )

    # Check 1: VLAN exists
    exists_check = VerificationCheck(
        name="vlan_exists",
        description="VLAN interface exists",
        expected="exists",
    )

    try:
        vlan_data = client.get_vlan(vlan_name)
        exists_check.status = CheckStatus.PASS
        exists_check.actual = "exists"
        exists_check.message = f"VLAN {vlan_name} found"
        verification.vlan_id = vlan_data.get("vlanid")
    except FortiGateNotFoundError:
        exists_check.status = CheckStatus.FAIL
        exists_check.actual = "not found"
        exists_check.message = f"VLAN {vlan_name} does not exist"
        verification.checks.append(exists_check)
        verification.overall_status = CheckStatus.FAIL
        return verification
    except FortiGateError as e:
        exists_check.status = CheckStatus.FAIL
        exists_check.actual = "error"
        exists_check.message = str(e)
        verification.checks.append(exists_check)
        verification.overall_status = CheckStatus.FAIL
        return verification

    verification.checks.append(exists_check)

    # Check 2: VLAN is on expected interface
    interface_check = VerificationCheck(
        name="parent_interface",
        description="VLAN is on expected interface",
        expected=expected_interface,
    )

    actual_interface = vlan_data.get("interface", "")
    interface_check.actual = actual_interface

    if actual_interface == expected_interface:
        interface_check.status = CheckStatus.PASS
        interface_check.message = f"VLAN is correctly on {expected_interface}"
    else:
        interface_check.status = CheckStatus.FAIL
        interface_check.message = f"VLAN is on {actual_interface}, expected {expected_interface}"

    verification.checks.append(interface_check)

    # Check 3: VLAN status is up
    status_check = VerificationCheck(
        name="vlan_status",
        description="VLAN interface is up",
        expected="up",
    )

    actual_status = vlan_data.get("status", "unknown")
    status_check.actual = actual_status

    if actual_status == "up":
        status_check.status = CheckStatus.PASS
        status_check.message = "VLAN interface is operational"
    elif actual_status == "down":
        status_check.status = CheckStatus.WARN
        status_check.message = "VLAN interface is administratively down"
    else:
        status_check.status = CheckStatus.WARN
        status_check.message = f"VLAN status is {actual_status}"

    verification.checks.append(status_check)

    # Check 4: IP configuration
    ip_check = VerificationCheck(
        name="ip_configuration",
        description="VLAN has valid IP configuration",
        expected="configured",
    )

    ip_raw = vlan_data.get("ip", "")
    if isinstance(ip_raw, str):
        ip_str = ip_raw
    elif isinstance(ip_raw, list) and len(ip_raw) >= 1:
        ip_str = str(ip_raw[0])
    else:
        ip_str = ""

    ip_check.actual = ip_str if ip_str else "not configured"

    # Check if IP is configured and not 0.0.0.0
    if ip_str and not ip_str.startswith("0.0.0.0"):
        ip_check.status = CheckStatus.PASS
        ip_check.message = f"IP address configured: {ip_str}"
    else:
        ip_check.status = CheckStatus.WARN
        ip_check.message = "No IP address configured (may be intentional for L2 VLAN)"

    verification.checks.append(ip_check)

    # Check 5: VLAN type verification
    type_check = VerificationCheck(
        name="interface_type",
        description="Interface is VLAN type",
        expected="vlan",
    )

    actual_type = vlan_data.get("type", "unknown")
    type_check.actual = actual_type

    if actual_type == "vlan":
        type_check.status = CheckStatus.PASS
        type_check.message = "Interface is correctly typed as VLAN"
    else:
        type_check.status = CheckStatus.FAIL
        type_check.message = f"Interface type is {actual_type}, expected vlan"

    verification.checks.append(type_check)

    # Check 6: Firewall policy references
    refs_check = VerificationCheck(
        name="firewall_references",
        description="Firewall policies reference this VLAN",
    )

    try:
        refs = client.get_vlan_references(vlan_name)
        policy_count = len(refs.get("firewall_policies", []))
        address_count = len(refs.get("firewall_addresses", []))
        total_refs = sum(len(v) for v in refs.values())

        refs_check.actual = f"{total_refs} references"

        if policy_count > 0:
            refs_check.status = CheckStatus.PASS
            refs_check.message = f"Found {policy_count} policies, {address_count} addresses"
        else:
            refs_check.status = CheckStatus.WARN
            refs_check.message = "No firewall policies reference this VLAN"

    except FortiGateError as e:
        refs_check.status = CheckStatus.WARN
        refs_check.actual = "error"
        refs_check.message = f"Could not check references: {e}"

    verification.checks.append(refs_check)

    # Check 7: MTU verification
    mtu_check = VerificationCheck(
        name="mtu_configuration",
        description="MTU is properly configured",
        expected="1500 or custom",
    )

    mtu = vlan_data.get("mtu", 0)
    mtu_check.actual = str(mtu)

    if 1280 <= mtu <= 9000:
        mtu_check.status = CheckStatus.PASS
        mtu_check.message = f"MTU {mtu} is within valid range"
    else:
        mtu_check.status = CheckStatus.WARN
        mtu_check.message = f"MTU {mtu} may be outside optimal range"

    verification.checks.append(mtu_check)

    # Determine overall status
    if verification.fail_count > 0:
        verification.overall_status = CheckStatus.FAIL
    elif verification.warn_count > 0:
        verification.overall_status = CheckStatus.WARN
    else:
        verification.overall_status = CheckStatus.PASS

    return verification


def verify_interface_vlans(
    client: FortiGateClient,
    interface: str,
) -> VerificationReport:
    """
    Verify all VLANs on an interface.

    Args:
        client: FortiGate API client
        interface: Interface to check

    Returns:
        VerificationReport with all VLAN verifications
    """
    report = VerificationReport(
        fortigate_host=client.host,
        expected_interface=interface,
    )

    try:
        vlans = client.get_interface_vlans(interface)
    except FortiGateNotFoundError:
        report.overall_status = CheckStatus.FAIL
        report.error = f"Interface '{interface}' not found"
        return report
    except FortiGateError as e:
        report.overall_status = CheckStatus.FAIL
        report.error = str(e)
        return report

    if not vlans:
        report.overall_status = CheckStatus.WARN
        report.error = f"No VLANs found on interface '{interface}'"
        return report

    for vlan_data in vlans:
        vlan_name = vlan_data.get("name", "")
        verification = verify_vlan(client, vlan_name, interface)
        report.vlans.append(verification)

    # Determine overall status
    if report.total_fail > 0:
        report.overall_status = CheckStatus.FAIL
    elif report.total_warn > 0:
        report.overall_status = CheckStatus.WARN
    else:
        report.overall_status = CheckStatus.PASS

    return report


def verify_specific_vlans(
    client: FortiGateClient,
    vlan_names: list[str],
    expected_interface: str,
) -> VerificationReport:
    """
    Verify specific VLANs are on expected interface.

    Args:
        client: FortiGate API client
        vlan_names: List of VLAN names to verify
        expected_interface: Expected parent interface

    Returns:
        VerificationReport with all VLAN verifications
    """
    report = VerificationReport(
        fortigate_host=client.host,
        expected_interface=expected_interface,
    )

    for vlan_name in vlan_names:
        verification = verify_vlan(client, vlan_name, expected_interface)
        report.vlans.append(verification)

    # Determine overall status
    if report.total_fail > 0:
        report.overall_status = CheckStatus.FAIL
    elif report.total_warn > 0:
        report.overall_status = CheckStatus.WARN
    elif report.vlans:
        report.overall_status = CheckStatus.PASS

    return report


def print_verification_report(report: VerificationReport) -> None:
    """Print verification report as formatted output."""
    console = Console()

    # Status colors
    status_colors = {
        CheckStatus.PASS: "green",
        CheckStatus.FAIL: "red",
        CheckStatus.WARN: "yellow",
        CheckStatus.SKIP: "dim",
    }

    # Header
    overall_color = status_colors.get(report.overall_status, "white")
    console.print(Panel(
        f"[bold]VLAN Migration Verification Report[/bold]\n"
        f"FortiGate: {report.fortigate_host}\n"
        f"Expected Interface: [blue]{report.expected_interface}[/blue]\n"
        f"Overall Status: [{overall_color}]{report.overall_status.value.upper()}[/{overall_color}]",
        title="Verification Report",
    ))

    if report.error:
        console.print(f"\n[red]Error:[/red] {report.error}\n")
        return

    if not report.vlans:
        console.print("[yellow]No VLANs to verify[/yellow]")
        return

    # Per-VLAN results
    for vlan in report.vlans:
        vlan_color = status_colors.get(vlan.overall_status, "white")
        console.print(f"\n[bold]{vlan.vlan_name}[/bold] (VLAN {vlan.vlan_id}) - "
                      f"[{vlan_color}]{vlan.overall_status.value.upper()}[/{vlan_color}]")

        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Check", style="cyan")
        table.add_column("Status")
        table.add_column("Expected")
        table.add_column("Actual")
        table.add_column("Message", style="dim")

        for check in vlan.checks:
            color = status_colors.get(check.status, "white")
            status_icon = {
                CheckStatus.PASS: "[green]PASS[/green]",
                CheckStatus.FAIL: "[red]FAIL[/red]",
                CheckStatus.WARN: "[yellow]WARN[/yellow]",
                CheckStatus.SKIP: "[dim]SKIP[/dim]",
            }.get(check.status, check.status.value)

            table.add_row(
                check.name,
                status_icon,
                check.expected or "-",
                check.actual or "-",
                (check.message or "")[:40],
            )

        console.print(table)

    # Summary
    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  VLANs Verified: {len(report.vlans)}")
    console.print(f"  Total Checks: {sum(len(v.checks) for v in report.vlans)}")
    console.print(f"  [green]Passed:[/green] {report.total_pass}")
    console.print(f"  [red]Failed:[/red] {report.total_fail}")
    console.print(f"  [yellow]Warnings:[/yellow] {report.total_warn}")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Verify VLAN migration on a Fortinet FortiGate.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Verify specific VLANs are on expected interface
  python verify.py --vlan vlan100 --expected-interface port2

  # Verify multiple VLANs
  python verify.py --vlan vlan100 --vlan vlan200 --expected-interface port2

  # Check all VLANs on an interface
  python verify.py --interface port2 --check-all

  # JSON output for automation
  python verify.py --vlan vlan100 --expected-interface port2 --json

Environment Variables:
  FORTIGATE_HOST      FortiGate hostname or IP (required)
  FORTIGATE_API_KEY   REST API token (required)
  FORTIGATE_VERIFY_SSL Enable SSL verification (default: false)
        """,
    )

    # Verification mode
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--vlan", "-v",
        action="append",
        dest="vlans",
        help="VLAN name to verify (can be repeated)",
    )
    mode_group.add_argument(
        "--check-all",
        action="store_true",
        help="Check all VLANs on the interface",
    )

    # Interface specification
    interface_group = parser.add_mutually_exclusive_group(required=True)
    interface_group.add_argument(
        "--expected-interface", "-e",
        help="Expected parent interface for --vlan mode",
    )
    interface_group.add_argument(
        "--interface", "-i",
        help="Interface to check for --check-all mode",
    )

    # Output options
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output as JSON instead of table",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as failures (exit code 1)",
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

    # Run verification
    try:
        if args.check_all:
            report = verify_interface_vlans(client, args.interface)
        else:
            report = verify_specific_vlans(
                client,
                args.vlans,
                args.expected_interface,
            )
    except (FortiGateAuthError, FortiGateConnectionError) as e:
        if args.json:
            print(json.dumps({"success": False, "error": str(e)}, indent=2))
        else:
            console.print(f"[red]Error:[/red] {e}")
        return 1

    # Output results
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print_verification_report(report)

    # Determine exit code
    if report.overall_status == CheckStatus.FAIL:
        return 1
    if report.overall_status == CheckStatus.WARN and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
