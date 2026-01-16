"""Tests for FortiGate API client.

These tests verify the bug fixes for:
1. Retry decorator scope - connection and rate limit errors should trigger retry
2. Interface structure parsing - srcintf/dstintf are lists of dicts, not strings
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import Mock, patch, call

import pytest
import requests

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from fortigate_client import (
    FortiGateClient,
    FortiGateConnectionError,
    FortiGateRateLimitError,
    FortiGateAuthError,
    FortiGateNotFoundError,
    FortiGateError,
    RateLimiter,
)


class TestRateLimiter:
    """Tests for RateLimiter class."""

    def test_first_request_immediate(self):
        """First request should not wait."""
        limiter = RateLimiter(min_interval=1.0)
        start = time.monotonic()
        limiter.wait()
        elapsed = time.monotonic() - start
        assert elapsed < 0.1  # Should be nearly instant

    def test_enforces_minimum_interval(self):
        """Second request should wait for minimum interval."""
        limiter = RateLimiter(min_interval=0.2)
        limiter.wait()  # First request
        start = time.monotonic()
        limiter.wait()  # Second request should wait
        elapsed = time.monotonic() - start
        assert elapsed >= 0.15  # Allow small margin


class TestClientInitialization:
    """Tests for client initialization."""

    def test_client_sets_headers(self):
        """Client should set proper authentication headers."""
        client = FortiGateClient(host="test.local", api_key="my-secret-key")
        assert client._session.headers["Authorization"] == "Bearer my-secret-key"
        assert client._session.headers["Content-Type"] == "application/json"

    def test_base_url(self):
        """Base URL should be constructed correctly."""
        client = FortiGateClient(host="firewall.example.com", api_key="key")
        assert client.base_url == "https://firewall.example.com/api/v2"

    def test_from_env_missing_host(self):
        """Should raise error if FORTIGATE_HOST not set."""
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(FortiGateError, match="FORTIGATE_HOST"):
                FortiGateClient.from_env()

    def test_from_env_missing_api_key(self):
        """Should raise error if FORTIGATE_API_KEY not set."""
        with patch.dict("os.environ", {"FORTIGATE_HOST": "test.local"}, clear=True):
            with pytest.raises(FortiGateError, match="FORTIGATE_API_KEY"):
                FortiGateClient.from_env()


class TestErrorHandling:
    """Tests for HTTP error handling."""

    def test_401_raises_auth_error(self, mock_client):
        """401 response should raise FortiGateAuthError."""
        mock_client._session.request.return_value = Mock(
            status_code=401,
            ok=False,
            text='{"error": "unauthorized"}',
            json=lambda: {"error": "unauthorized"},
        )
        with pytest.raises(FortiGateAuthError, match="Authentication failed"):
            mock_client.get("/test")

    def test_403_raises_auth_error(self, mock_client):
        """403 response should raise FortiGateAuthError."""
        mock_client._session.request.return_value = Mock(
            status_code=403,
            ok=False,
            text='{"error": "forbidden"}',
            json=lambda: {"error": "forbidden"},
        )
        with pytest.raises(FortiGateAuthError, match="Access forbidden"):
            mock_client.get("/test")

    def test_404_raises_not_found_error(self, mock_client):
        """404 response should raise FortiGateNotFoundError."""
        mock_client._session.request.return_value = Mock(
            status_code=404,
            ok=False,
            text='{"error": "not found"}',
            json=lambda: {"error": "not found"},
            url="https://test.local/api/v2/test",
        )
        with pytest.raises(FortiGateNotFoundError, match="not found"):
            mock_client.get("/test")

    def test_429_raises_rate_limit_error(self, mock_client):
        """429 response should raise FortiGateRateLimitError."""
        # All 3 attempts return 429
        mock_client._session.request.return_value = Mock(
            status_code=429,
            ok=False,
            text='{"error": "rate limit"}',
            json=lambda: {"error": "rate limit"},
        )
        with pytest.raises(FortiGateRateLimitError, match="Rate limit"):
            mock_client.get("/test")


class TestRetryBehavior:
    """Tests for retry logic - BUG FIX #1.

    These tests verify that the retry decorator correctly handles:
    - FortiGateConnectionError (wrapped from requests.ConnectionError)
    - FortiGateRateLimitError (from 429 responses)
    """

    def test_retry_on_connection_error_eventual_success(self, mock_client):
        """Connection errors should be retried and succeed when connection recovers.

        BUG FIX: The retry decorator now catches FortiGateConnectionError
        instead of requests.ConnectionError (which gets wrapped).
        """
        # Sequence: fail twice, then succeed
        mock_client._session.request.side_effect = [
            requests.ConnectionError("Connection refused"),
            requests.ConnectionError("Connection refused"),
            Mock(
                status_code=200,
                ok=True,
                text='{"results": []}',
                json=lambda: {"results": []},
            ),
        ]

        result = mock_client.get("/cmdb/system/interface")

        assert result == {"results": []}
        assert mock_client._session.request.call_count == 3

    def test_retry_on_connection_error_max_attempts(self, mock_client):
        """Should give up after 3 connection failures."""
        mock_client._session.request.side_effect = requests.ConnectionError(
            "Persistent failure"
        )

        with pytest.raises(FortiGateConnectionError, match="Connection failed"):
            mock_client.get("/test")

        assert mock_client._session.request.call_count == 3

    def test_retry_on_rate_limit_eventual_success(self, mock_client):
        """Rate limit errors should be retried and succeed when limit clears.

        BUG FIX: FortiGateRateLimitError raised from _handle_response()
        is now properly caught by the retry decorator.
        """
        # Sequence: 429 twice, then 200
        mock_client._session.request.side_effect = [
            Mock(
                status_code=429,
                ok=False,
                text='{"error": "rate limit"}',
                json=lambda: {"error": "rate limit"},
            ),
            Mock(
                status_code=429,
                ok=False,
                text='{"error": "rate limit"}',
                json=lambda: {"error": "rate limit"},
            ),
            Mock(
                status_code=200,
                ok=True,
                text='{"results": ["data"]}',
                json=lambda: {"results": ["data"]},
            ),
        ]

        result = mock_client.get("/cmdb/system/interface")

        assert result == {"results": ["data"]}
        assert mock_client._session.request.call_count == 3

    def test_retry_on_rate_limit_max_attempts(self, mock_client):
        """Should give up after 3 rate limit failures."""
        mock_client._session.request.return_value = Mock(
            status_code=429,
            ok=False,
            text='{"error": "rate limit"}',
            json=lambda: {"error": "rate limit"},
        )

        with pytest.raises(FortiGateRateLimitError, match="Rate limit"):
            mock_client.get("/test")

        assert mock_client._session.request.call_count == 3

    def test_no_retry_on_auth_error(self, mock_client):
        """Auth errors should NOT be retried (not transient)."""
        mock_client._session.request.return_value = Mock(
            status_code=401,
            ok=False,
            text='{"error": "unauthorized"}',
            json=lambda: {"error": "unauthorized"},
        )

        with pytest.raises(FortiGateAuthError):
            mock_client.get("/test")

        # Should NOT retry - only 1 attempt
        assert mock_client._session.request.call_count == 1

    def test_no_retry_on_not_found_error(self, mock_client):
        """404 errors should NOT be retried (not transient)."""
        mock_client._session.request.return_value = Mock(
            status_code=404,
            ok=False,
            text='{"error": "not found"}',
            json=lambda: {"error": "not found"},
            url="https://test.local/test",
        )

        with pytest.raises(FortiGateNotFoundError):
            mock_client.get("/test")

        # Should NOT retry - only 1 attempt
        assert mock_client._session.request.call_count == 1


class TestVlanReferences:
    """Tests for VLAN reference detection - BUG FIX #2.

    These tests verify that get_vlan_references() correctly parses
    the FortiGate API response structure where interfaces are returned as:
    [{"name": "interface_name"}] NOT ["interface_name"]
    """

    def test_vlan_references_firewall_policies_src_interface(
        self, mock_client, sample_policy_data
    ):
        """Should find VLAN when it's a source interface.

        BUG FIX: The code now extracts interface names from dict structure:
        [{"name": "vlan100"}] instead of expecting ["vlan100"]
        """
        # Mock GET for policies endpoint
        mock_client._session.request.side_effect = [
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: sample_policy_data,
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
        ]

        refs = mock_client.get_vlan_references("vlan100")

        # Policy 1 has vlan100 as srcintf, Policy 2 has vlan100 as dstintf
        assert "1" in refs["firewall_policies"]
        assert "2" in refs["firewall_policies"]
        assert "3" not in refs["firewall_policies"]  # This one doesn't use vlan100

    def test_vlan_references_firewall_policies_dst_interface(
        self, mock_client, sample_policy_data
    ):
        """Should find VLAN when it's a destination interface."""
        mock_client._session.request.side_effect = [
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: sample_policy_data,
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
        ]

        refs = mock_client.get_vlan_references("wan1")

        # Policy 1 has wan1 as dstintf
        assert "1" in refs["firewall_policies"]
        assert "2" not in refs["firewall_policies"]

    def test_vlan_references_no_match(self, mock_client, sample_policy_data):
        """Should return empty list when VLAN is not referenced."""
        mock_client._session.request.side_effect = [
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: sample_policy_data,
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
        ]

        refs = mock_client.get_vlan_references("vlan999")

        assert refs["firewall_policies"] == []

    def test_vlan_references_firewall_addresses(
        self, mock_client, sample_address_data
    ):
        """Should find VLAN in firewall address associations."""
        mock_client._session.request.side_effect = [
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: sample_address_data,
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
        ]

        refs = mock_client.get_vlan_references("vlan100")

        assert "VLAN100_Subnet" in refs["firewall_addresses"]
        assert "Server_IP" not in refs["firewall_addresses"]

    def test_vlan_references_dhcp_servers(self, mock_client, sample_dhcp_data):
        """Should find VLAN in DHCP server configurations."""
        mock_client._session.request.side_effect = [
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: sample_dhcp_data,
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
        ]

        refs = mock_client.get_vlan_references("vlan100")

        assert "1" in refs["dhcp_servers"]
        assert "2" not in refs["dhcp_servers"]

    def test_vlan_references_static_routes(self, mock_client, sample_route_data):
        """Should find VLAN in static route configurations."""
        mock_client._session.request.side_effect = [
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: sample_route_data,
            ),
        ]

        refs = mock_client.get_vlan_references("vlan100")

        assert "1" in refs["static_routes"]
        assert "2" not in refs["static_routes"]

    def test_vlan_references_handles_api_errors_gracefully(self, mock_client):
        """Should continue checking other resources if one API call fails."""
        # First call (policies) fails, others succeed
        mock_client._session.request.side_effect = [
            Mock(
                status_code=500,
                ok=False,
                text='{"error": "internal"}',
                json=lambda: {"error": "internal"},
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {
                    "results": [
                        {"name": "Test_Address", "associated-interface": "vlan100"}
                    ]
                },
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
            Mock(
                status_code=200,
                ok=True,
                text="{}",
                json=lambda: {"results": []},
            ),
        ]

        refs = mock_client.get_vlan_references("vlan100")

        # Should still find the address even though policies failed
        assert refs["firewall_policies"] == []  # Failed gracefully
        assert "Test_Address" in refs["firewall_addresses"]


class TestVlanOperations:
    """Tests for VLAN CRUD operations."""

    def test_get_interface_vlans_filters_by_parent(self, mock_client):
        """Should only return VLANs belonging to specified parent interface."""
        mock_client._session.request.return_value = Mock(
            status_code=200,
            ok=True,
            text="{}",
            json=lambda: {
                "results": [
                    {"name": "vlan100", "type": "vlan", "interface": "port1", "vlanid": 100},
                    {"name": "vlan200", "type": "vlan", "interface": "port2", "vlanid": 200},
                    {"name": "port1", "type": "physical", "interface": ""},
                ]
            },
        )

        vlans = mock_client.get_interface_vlans("port1")

        assert len(vlans) == 1
        assert vlans[0]["name"] == "vlan100"

    def test_get_interface_vlans_sorted_by_vlan_id(self, mock_client):
        """Should return VLANs sorted by VLAN ID."""
        mock_client._session.request.return_value = Mock(
            status_code=200,
            ok=True,
            text="{}",
            json=lambda: {
                "results": [
                    {"name": "vlan300", "type": "vlan", "interface": "port1", "vlanid": 300},
                    {"name": "vlan100", "type": "vlan", "interface": "port1", "vlanid": 100},
                    {"name": "vlan200", "type": "vlan", "interface": "port1", "vlanid": 200},
                ]
            },
        )

        vlans = mock_client.get_interface_vlans("port1")

        assert [v["vlanid"] for v in vlans] == [100, 200, 300]

    def test_create_vlan_with_ip(self, mock_client):
        """Should create VLAN with IP configuration."""
        mock_client._session.request.return_value = Mock(
            status_code=200,
            ok=True,
            text="{}",
            json=lambda: {"status": "success"},
        )

        result = mock_client.create_vlan(
            name="vlan100",
            vlan_id=100,
            parent_interface="port1",
            ip="10.0.100.1",
            netmask="255.255.255.0",
        )

        assert result["status"] == "success"
        call_args = mock_client._session.request.call_args
        assert call_args[1]["json"]["ip"] == "10.0.100.1 255.255.255.0"

    def test_get_vlan_validates_type(self, mock_client):
        """Should raise error if interface is not a VLAN."""
        mock_client._session.request.return_value = Mock(
            status_code=200,
            ok=True,
            text="{}",
            json=lambda: {"results": [{"name": "port1", "type": "physical"}]},
        )

        with pytest.raises(FortiGateError, match="not a VLAN"):
            mock_client.get_vlan("port1")
