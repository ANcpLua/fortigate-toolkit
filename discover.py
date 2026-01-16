#!/usr/bin/env python3
"""
VLAN Discovery Tool for Fortinet FortiGate.

Lists all VLANs on a given interface with detailed information.
Read-only operation - makes no changes to the firewall.

Usage:
    python discover.py --interface port1
    python discover.py --interface port1 --json
    python discover.py --all --json

Environment Variables:
    FORTIGATE_HOST: FortiGate hostname or IP (required)
    FORTIGATE_API_KEY: REST API token (required)
    FORTIGATE_VERIFY_SSL: Enable SSL verification (default: false)
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from typing import Any

from rich.console import Console
from rich.table import Table

from fortigate_client import (
    FortiGateClient,
    FortiGateAuthError,
    FortiGateConnectionError,
    FortiGateError,
    FortiGateNotFoundError,
)


@dataclass
class VlanInfo:
    """Structured VLAN information for output."""

    name: str
    vlan_id: int
    parent_interface: str
    ip: str
    status: str
    vdom: str
    description: str
    mtu: int
    references: dict[str, list[str]]

    @classmethod
    def from_api_response(cls, data: dict[str, Any], references: dict[str, list[str]]) -> VlanInfo:
        """Create VlanInfo from FortiGate API response."""
        # Parse IP - FortiGate returns "ip netmask" format
        ip_raw = data.get("ip", "0.0.0.0 0.0.0.0")
        if isinstance(ip_raw, str):
            ip = ip_raw
        elif isinstance(ip_raw, list) and len(ip_raw) >= 2:
            ip = f"{ip_raw[0]}/{ip_raw[1]}"
        else:
            ip = "N/A"

        return cls(
            name=data.get("name", ""),
            vlan_id=data.get("vlanid", 0),
            parent_interface=data.get("interface", ""),
            ip=ip,
            status=data.get("status", "unknown"),
            vdom=data.get("vdom", "root"),
            description=data.get("description", ""),
            mtu=data.get("mtu", 1500),
            references=references,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return asdict(self)


@dataclass
class DiscoveryResult:
    """Result of VLAN discovery operation."""

    success: bool
    interface: str | None
    vlans: list[VlanInfo]
    error: str | None = None
    fortigate_host: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "success": self.success,
            "fortigate_host": self.fortigate_host,
            "interface": self.interface,
            "vlan_count": len(self.vlans),
            "vlans": [v.to_dict() for v in self.vlans],
            "error": self.error,
        }


def discover_vlans(
    client: FortiGateClient,
    interface: str | None = None,
    include_references: bool = True,
) -> DiscoveryResult:
    """
    Discover VLANs on the FortiGate.

    Args:
        client: FortiGate API client
        interface: Specific interface to query (None = all)
        include_references: Include firewall policy references

    Returns:
        DiscoveryResult with VLAN information
    """
    try:
        if interface:
            # Verify interface exists first
            try:
                client.get_interface(interface)
            except FortiGateNotFoundError:
                return DiscoveryResult(
                    success=False,
                    interface=interface,
                    vlans=[],
                    error=f"Interface '{interface}' not found",
                    fortigate_host=client.host,
                )

            raw_vlans = client.get_interface_vlans(interface)
        else:
            # Get all VLANs across all interfaces
            all_interfaces = client.get_all_interfaces()
            raw_vlans = [i for i in all_interfaces if i.get("type") == "vlan"]

        vlans = []
        for raw_vlan in raw_vlans:
            refs = {}
            if include_references:
                try:
                    refs = client.get_vlan_references(raw_vlan.get("name", ""))
                except FortiGateError:
                    refs = {"error": ["Failed to fetch references"]}

            vlans.append(VlanInfo.from_api_response(raw_vlan, refs))

        return DiscoveryResult(
            success=True,
            interface=interface,
            vlans=vlans,
            fortigate_host=client.host,
        )

    except FortiGateAuthError as e:
        return DiscoveryResult(
            success=False,
            interface=interface,
            vlans=[],
            error=f"Authentication failed: {e}",
            fortigate_host=client.host,
        )
    except FortiGateConnectionError as e:
        return DiscoveryResult(
            success=False,
            interface=interface,
            vlans=[],
            error=f"Connection failed: {e}",
            fortigate_host=client.host,
        )
    except FortiGateError as e:
        return DiscoveryResult(
            success=False,
            interface=interface,
            vlans=[],
            error=str(e),
            fortigate_host=client.host,
        )


def print_table_output(result: DiscoveryResult, show_references: bool = False) -> None:
    """Print discovery results as a formatted table."""
    console = Console()

    if not result.success:
        console.print(f"[red]Error:[/red] {result.error}")
        return

    if not result.vlans:
        scope = f"on interface '{result.interface}'" if result.interface else "on this FortiGate"
        console.print(f"[yellow]No VLANs found {scope}[/yellow]")
        return

    # Header
    scope = f"Interface: {result.interface}" if result.interface else "All Interfaces"
    console.print(f"\n[bold]VLAN Discovery - {result.fortigate_host}[/bold]")
    console.print(f"[dim]{scope}[/dim]\n")

    # Main table
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Name", style="green")
    table.add_column("VLAN ID", justify="right")
    table.add_column("Parent", style="blue")
    table.add_column("IP Address")
    table.add_column("Status")
    table.add_column("VDOM")

    if show_references:
        table.add_column("References", style="yellow")

    for vlan in result.vlans:
        status_style = "green" if vlan.status == "up" else "red"
        status_display = f"[{status_style}]{vlan.status}[/{status_style}]"

        row = [
            vlan.name,
            str(vlan.vlan_id),
            vlan.parent_interface,
            vlan.ip,
            status_display,
            vlan.vdom,
        ]

        if show_references:
            ref_count = sum(len(v) for v in vlan.references.values())
            row.append(str(ref_count))

        table.add_row(*row)

    console.print(table)
    console.print(f"\n[dim]Total VLANs: {len(result.vlans)}[/dim]")

    # Reference details if requested
    if show_references:
        console.print("\n[bold]Reference Details:[/bold]")
        for vlan in result.vlans:
            has_refs = any(vlan.references.values())
            if has_refs:
                console.print(f"\n  [green]{vlan.name}[/green] (VLAN {vlan.vlan_id}):")
                for ref_type, refs in vlan.references.items():
                    if refs:
                        ref_type_display = ref_type.replace("_", " ").title()
                        console.print(f"    {ref_type_display}: {', '.join(refs)}")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Discover VLANs on a Fortinet FortiGate firewall.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List VLANs on a specific interface
  python discover.py --interface port1

  # List all VLANs with JSON output
  python discover.py --all --json

  # List VLANs with reference information
  python discover.py --interface port1 --show-references

Environment Variables:
  FORTIGATE_HOST      FortiGate hostname or IP (required)
  FORTIGATE_API_KEY   REST API token (required)
  FORTIGATE_VERIFY_SSL Enable SSL verification (default: false)
        """,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--interface", "-i",
        help="Physical interface to query (e.g., port1, wan1)",
    )
    group.add_argument(
        "--all", "-a",
        action="store_true",
        help="List VLANs across all interfaces",
    )

    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output as JSON instead of table",
    )
    parser.add_argument(
        "--show-references", "-r",
        action="store_true",
        help="Include firewall policy references (slower)",
    )
    parser.add_argument(
        "--no-references",
        action="store_true",
        help="Skip reference lookup (faster)",
    )

    args = parser.parse_args()

    try:
        client = FortiGateClient.from_env()
    except FortiGateError as e:
        if args.json:
            print(json.dumps({"success": False, "error": str(e)}, indent=2))
        else:
            Console().print(f"[red]Configuration Error:[/red] {e}")
        return 1

    # Determine interface filter
    interface = None if args.all else args.interface

    # Determine whether to include references
    include_refs = not args.no_references

    # Run discovery
    result = discover_vlans(
        client=client,
        interface=interface,
        include_references=include_refs,
    )

    # Output results
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_table_output(result, show_references=args.show_references)

    return 0 if result.success else 1


if __name__ == "__main__":
    sys.exit(main())
