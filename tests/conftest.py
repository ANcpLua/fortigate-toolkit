"""Shared test fixtures for FortiGate toolkit tests."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from fortigate_client import FortiGateClient


@pytest.fixture
def mock_client():
    """Fixture providing a FortiGateClient with mocked session."""
    client = FortiGateClient(host="test.local", api_key="fake-api-key")
    client._session.request = Mock()
    return client


@pytest.fixture
def sample_vlan_data():
    """Fixture providing realistic VLAN API response."""
    return {
        "name": "vlan100",
        "type": "vlan",
        "vlanid": 100,
        "interface": "port1",
        "ip": "10.0.100.1 255.255.255.0",
        "status": "up",
        "vdom": "root",
        "mtu": 1500,
    }


@pytest.fixture
def sample_policy_data():
    """Fixture providing realistic firewall policy with CORRECT structure.

    FortiGate API returns interfaces as list of dicts: [{"name": "interface_name"}]
    NOT as list of strings: ["interface_name"]
    """
    return {
        "results": [
            {
                "policyid": 1,
                "name": "Allow_VLAN100_to_Internet",
                "srcintf": [{"name": "vlan100"}],  # Correct FortiGate API structure
                "dstintf": [{"name": "wan1"}],
                "action": "accept",
            },
            {
                "policyid": 2,
                "name": "Allow_LAN_to_VLAN100",
                "srcintf": [{"name": "port1"}],
                "dstintf": [{"name": "vlan100"}],  # VLAN in destination
                "action": "accept",
            },
            {
                "policyid": 3,
                "name": "Deny_All",
                "srcintf": [{"name": "any"}],
                "dstintf": [{"name": "any"}],
                "action": "deny",
            },
        ]
    }


@pytest.fixture
def sample_address_data():
    """Fixture providing realistic firewall address response."""
    return {
        "results": [
            {
                "name": "VLAN100_Subnet",
                "associated-interface": "vlan100",
                "subnet": "10.0.100.0 255.255.255.0",
            },
            {
                "name": "Server_IP",
                "associated-interface": "port1",
                "subnet": "192.168.1.10 255.255.255.255",
            },
        ]
    }


@pytest.fixture
def sample_dhcp_data():
    """Fixture providing realistic DHCP server response."""
    return {
        "results": [
            {
                "id": 1,
                "interface": "vlan100",
                "lease-time": 86400,
            },
            {
                "id": 2,
                "interface": "port1",
                "lease-time": 86400,
            },
        ]
    }


@pytest.fixture
def sample_route_data():
    """Fixture providing realistic static route response."""
    return {
        "results": [
            {
                "seq-num": 1,
                "device": "vlan100",
                "gateway": "10.0.100.254",
            },
            {
                "seq-num": 2,
                "device": "wan1",
                "gateway": "0.0.0.0",
            },
        ]
    }
