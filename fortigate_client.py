"""
FortiGate API Client with rate limiting and retry logic.

Production-ready client for FortiOS REST API interactions.
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import requests
import urllib3
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

# Suppress InsecureRequestWarning for self-signed certs (common in FortiGate)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FortiGateError(Exception):
    """Base exception for FortiGate API errors."""

    def __init__(self, message: str, status_code: int | None = None, response: dict | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response or {}


class FortiGateAuthError(FortiGateError):
    """Authentication failed."""


class FortiGateNotFoundError(FortiGateError):
    """Resource not found."""


class FortiGateRateLimitError(FortiGateError):
    """Rate limit exceeded."""


class FortiGateConnectionError(FortiGateError):
    """Connection to FortiGate failed."""


@dataclass
class RateLimiter:
    """Simple rate limiter ensuring minimum interval between requests."""

    min_interval: float = 1.0  # seconds between requests
    _last_request: float = field(default=0.0, init=False, repr=False)

    def wait(self) -> None:
        """Block until rate limit allows next request."""
        now = time.monotonic()
        elapsed = now - self._last_request
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_request = time.monotonic()


@dataclass
class FortiGateClient:
    """
    Production-ready FortiGate API client.

    Features:
    - Rate limiting (configurable, default 1 req/sec)
    - Automatic retry with exponential backoff
    - Proper error handling with specific exceptions
    - SSL verification toggle (for self-signed certs)

    Usage:
        client = FortiGateClient.from_env()
        vlans = client.get_interface_vlans("port1")
    """

    host: str
    api_key: str
    verify_ssl: bool = False
    timeout: int = 30
    rate_limit: float = 1.0  # requests per second
    _rate_limiter: RateLimiter = field(init=False, repr=False)
    _session: requests.Session = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._rate_limiter = RateLimiter(min_interval=self.rate_limit)
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        self._session.verify = self.verify_ssl

    @classmethod
    def from_env(cls) -> FortiGateClient:
        """
        Create client from environment variables.

        Required:
            FORTIGATE_HOST: FortiGate hostname or IP
            FORTIGATE_API_KEY: REST API token

        Optional:
            FORTIGATE_VERIFY_SSL: "true" or "false" (default: false)
            FORTIGATE_TIMEOUT: Request timeout in seconds (default: 30)
            FORTIGATE_RATE_LIMIT: Seconds between requests (default: 1.0)
        """
        host = os.environ.get("FORTIGATE_HOST")
        api_key = os.environ.get("FORTIGATE_API_KEY")

        if not host:
            raise FortiGateError("FORTIGATE_HOST environment variable not set")
        if not api_key:
            raise FortiGateError("FORTIGATE_API_KEY environment variable not set")

        verify_ssl = os.environ.get("FORTIGATE_VERIFY_SSL", "false").lower() == "true"
        timeout = int(os.environ.get("FORTIGATE_TIMEOUT", "30"))
        rate_limit = float(os.environ.get("FORTIGATE_RATE_LIMIT", "1.0"))

        return cls(
            host=host.rstrip("/"),
            api_key=api_key,
            verify_ssl=verify_ssl,
            timeout=timeout,
            rate_limit=rate_limit,
        )

    @property
    def base_url(self) -> str:
        """Return the base API URL."""
        protocol = "https"
        return f"{protocol}://{self.host}/api/v2"

    def _handle_response(self, response: requests.Response) -> dict[str, Any]:
        """Parse response and raise appropriate exceptions."""
        try:
            data = response.json() if response.text else {}
        except ValueError:
            data = {"raw_response": response.text}

        if response.status_code == 401:
            raise FortiGateAuthError(
                "Authentication failed. Check API key.",
                status_code=401,
                response=data,
            )
        elif response.status_code == 403:
            raise FortiGateAuthError(
                "Access forbidden. Check API key permissions.",
                status_code=403,
                response=data,
            )
        elif response.status_code == 404:
            raise FortiGateNotFoundError(
                f"Resource not found: {response.url}",
                status_code=404,
                response=data,
            )
        elif response.status_code == 429:
            raise FortiGateRateLimitError(
                "Rate limit exceeded",
                status_code=429,
                response=data,
            )
        elif response.status_code >= 500:
            raise FortiGateError(
                f"Server error: {response.status_code}",
                status_code=response.status_code,
                response=data,
            )
        elif not response.ok:
            raise FortiGateError(
                f"Request failed: {response.status_code}",
                status_code=response.status_code,
                response=data,
            )

        return data

    @retry(
        retry=retry_if_exception_type((FortiGateConnectionError, FortiGateRateLimitError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,  # Re-raise original exception, not tenacity.RetryError
    )
    def _request(
        self,
        method: str,
        endpoint: str,
        params: dict | None = None,
        json_data: dict | None = None,
    ) -> dict[str, Any]:
        """Execute API request with rate limiting and retry logic."""
        self._rate_limiter.wait()

        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        try:
            response = self._session.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
                timeout=self.timeout,
            )
        except requests.ConnectionError as e:
            raise FortiGateConnectionError(f"Connection failed: {e}") from e
        except requests.Timeout as e:
            raise FortiGateConnectionError(f"Request timed out: {e}") from e

        return self._handle_response(response)

    def get(self, endpoint: str, params: dict | None = None) -> dict[str, Any]:
        """Execute GET request."""
        return self._request("GET", endpoint, params=params)

    def post(self, endpoint: str, data: dict) -> dict[str, Any]:
        """Execute POST request."""
        return self._request("POST", endpoint, json_data=data)

    def put(self, endpoint: str, data: dict) -> dict[str, Any]:
        """Execute PUT request."""
        return self._request("PUT", endpoint, json_data=data)

    def delete(self, endpoint: str) -> dict[str, Any]:
        """Execute DELETE request."""
        return self._request("DELETE", endpoint)

    # -------------------------------------------------------------------------
    # VLAN-specific methods
    # -------------------------------------------------------------------------

    def get_all_interfaces(self) -> list[dict[str, Any]]:
        """Get all interfaces from FortiGate."""
        response = self.get("/cmdb/system/interface")
        return response.get("results", [])

    def get_interface(self, name: str) -> dict[str, Any]:
        """Get a specific interface by name."""
        response = self.get(f"/cmdb/system/interface/{name}")
        results = response.get("results", [])
        if not results:
            raise FortiGateNotFoundError(f"Interface '{name}' not found")
        return results[0]

    def get_interface_vlans(self, parent_interface: str) -> list[dict[str, Any]]:
        """
        Get all VLAN sub-interfaces for a given parent interface.

        Args:
            parent_interface: Name of the physical interface (e.g., "port1")

        Returns:
            List of VLAN interface configurations
        """
        all_interfaces = self.get_all_interfaces()
        vlans = [
            iface for iface in all_interfaces
            if iface.get("interface") == parent_interface
            and iface.get("type") == "vlan"
        ]
        return sorted(vlans, key=lambda x: x.get("vlanid", 0))

    def get_vlan(self, vlan_name: str) -> dict[str, Any]:
        """Get a specific VLAN interface by name."""
        iface = self.get_interface(vlan_name)
        if iface.get("type") != "vlan":
            raise FortiGateError(f"Interface '{vlan_name}' is not a VLAN (type: {iface.get('type')})")
        return iface

    def create_vlan(
        self,
        name: str,
        vlan_id: int,
        parent_interface: str,
        ip: str | None = None,
        netmask: str | None = None,
        vdom: str = "root",
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Create a new VLAN interface.

        Args:
            name: Name for the VLAN interface
            vlan_id: VLAN ID (1-4094)
            parent_interface: Physical interface to attach VLAN to
            ip: IP address (optional)
            netmask: Subnet mask (optional)
            vdom: Virtual domain (default: "root")
            **kwargs: Additional interface parameters

        Returns:
            API response
        """
        data = {
            "name": name,
            "type": "vlan",
            "vlanid": vlan_id,
            "interface": parent_interface,
            "vdom": vdom,
            **kwargs,
        }

        if ip and netmask:
            data["ip"] = f"{ip} {netmask}"
        elif ip:
            data["ip"] = ip

        return self.post("/cmdb/system/interface", data)

    def update_vlan(self, name: str, **kwargs: Any) -> dict[str, Any]:
        """
        Update an existing VLAN interface.

        Args:
            name: VLAN interface name
            **kwargs: Fields to update

        Returns:
            API response
        """
        # First verify it exists and is a VLAN
        self.get_vlan(name)
        return self.put(f"/cmdb/system/interface/{name}", kwargs)

    def delete_vlan(self, name: str) -> dict[str, Any]:
        """
        Delete a VLAN interface.

        Args:
            name: VLAN interface name

        Returns:
            API response
        """
        # First verify it exists and is a VLAN
        self.get_vlan(name)
        return self.delete(f"/cmdb/system/interface/{name}")

    def get_vlan_references(self, vlan_name: str) -> dict[str, list[str]]:
        """
        Find all firewall objects that reference a VLAN.

        This is critical before migration to understand dependencies.

        Returns:
            Dictionary with reference types as keys and lists of object names
        """
        references: dict[str, list[str]] = {
            "firewall_policies": [],
            "firewall_addresses": [],
            "dhcp_servers": [],
            "static_routes": [],
        }

        # Check firewall policies
        try:
            policies = self.get("/cmdb/firewall/policy").get("results", [])
            for policy in policies:
                # FortiGate API returns interfaces as list of dicts: [{"name": "port1"}]
                src_names = [intf.get("name", "") for intf in policy.get("srcintf", [])]
                dst_names = [intf.get("name", "") for intf in policy.get("dstintf", [])]
                if vlan_name in (src_names + dst_names):
                    references["firewall_policies"].append(str(policy.get("policyid")))
        except FortiGateError:
            pass

        # Check firewall addresses
        try:
            addresses = self.get("/cmdb/firewall/address").get("results", [])
            for addr in addresses:
                if addr.get("associated-interface") == vlan_name:
                    references["firewall_addresses"].append(addr.get("name", ""))
        except FortiGateError:
            pass

        # Check DHCP servers
        try:
            dhcp_servers = self.get("/cmdb/system.dhcp/server").get("results", [])
            for server in dhcp_servers:
                if server.get("interface") == vlan_name:
                    references["dhcp_servers"].append(str(server.get("id")))
        except FortiGateError:
            pass

        # Check static routes
        try:
            routes = self.get("/cmdb/router/static").get("results", [])
            for route in routes:
                if route.get("device") == vlan_name:
                    references["static_routes"].append(str(route.get("seq-num")))
        except FortiGateError:
            pass

        return references

    def test_connectivity(self) -> dict[str, Any]:
        """
        Test connectivity to FortiGate.

        Returns:
            System status information
        """
        return self.get("/monitor/system/status")
