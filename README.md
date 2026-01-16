# VLAN Migration Toolkit for Fortinet FortiOS

Production-ready Python toolkit for migrating VLANs between interfaces on Fortinet FortiGate firewalls.

## Features

- **Discovery**: List all VLANs on an interface with dependency tracking
- **Migration**: Move VLANs between interfaces with dry-run support
- **Verification**: Confirm migrations completed successfully
- **Safety**: Rate limiting, retry logic, comprehensive error handling
- **Automation**: JSON output for CI/CD integration

## Requirements

- Python 3.10+
- FortiGate with REST API enabled
- API token with read/write permissions for system interfaces

## Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

## Configuration

Set environment variables:

```bash
export FORTIGATE_HOST="192.168.1.1"        # Required: FortiGate IP/hostname
export FORTIGATE_API_KEY="your-api-token"  # Required: REST API token
export FORTIGATE_VERIFY_SSL="false"        # Optional: SSL verification (default: false)
export FORTIGATE_TIMEOUT="30"              # Optional: Request timeout in seconds
export FORTIGATE_RATE_LIMIT="1.0"          # Optional: Seconds between requests
```

### Creating an API Token

1. Log into FortiGate GUI
2. Navigate to **System > Administrators**
3. Create new REST API Admin
4. Generate and save the API token
5. Ensure the admin profile has permissions for:
   - `system.interface` (read/write)
   - `firewall.policy` (read)
   - `firewall.address` (read)
   - `router.static` (read)
   - `system.dhcp.server` (read)

## Usage

### 1. Discover VLANs

List all VLANs on a specific interface:

```bash
python discover.py --interface port1
```

List all VLANs with dependency information:

```bash
python discover.py --interface port1 --show-references
```

List all VLANs across all interfaces:

```bash
python discover.py --all
```

JSON output for automation:

```bash
python discover.py --interface port1 --json
```

### 2. Migrate VLANs

**Always run with `--dry-run` first!**

Preview migration of a single VLAN:

```bash
python migrate.py --vlan vlan100 --from-interface port1 --to-interface port2 --dry-run
```

Execute migration:

```bash
python migrate.py --vlan vlan100 --from-interface port1 --to-interface port2
```

Migrate all VLANs from an interface:

```bash
python migrate.py --all-vlans --from-interface port1 --to-interface port2 --dry-run
```

Skip confirmation prompt (for automation):

```bash
python migrate.py --vlan vlan100 --from-interface port1 --to-interface port2 --force --json
```

### 3. Verify Migration

Verify specific VLANs are on expected interface:

```bash
python verify.py --vlan vlan100 --expected-interface port2
```

Verify multiple VLANs:

```bash
python verify.py --vlan vlan100 --vlan vlan200 --expected-interface port2
```

Check all VLANs on an interface:

```bash
python verify.py --interface port2 --check-all
```

Strict mode (treat warnings as failures):

```bash
python verify.py --vlan vlan100 --expected-interface port2 --strict
```

## Complete Migration Workflow

```bash
# Step 1: Discover current state
python discover.py --interface port1 --show-references --json > before.json

# Step 2: Preview migration
python migrate.py --all-vlans --from-interface port1 --to-interface port2 --dry-run

# Step 3: Execute migration
python migrate.py --all-vlans --from-interface port1 --to-interface port2

# Step 4: Verify migration
python verify.py --interface port2 --check-all --strict

# Step 5: Document final state
python discover.py --interface port2 --show-references --json > after.json
```

## JSON Output Schema

All tools support `--json` for structured output:

### discover.py

```json
{
  "success": true,
  "fortigate_host": "192.168.1.1",
  "interface": "port1",
  "vlan_count": 3,
  "vlans": [
    {
      "name": "vlan100",
      "vlan_id": 100,
      "parent_interface": "port1",
      "ip": "10.0.100.1 255.255.255.0",
      "status": "up",
      "vdom": "root",
      "description": "Management VLAN",
      "mtu": 1500,
      "references": {
        "firewall_policies": ["1", "5"],
        "firewall_addresses": ["mgmt-net"],
        "dhcp_servers": [],
        "static_routes": []
      }
    }
  ],
  "error": null
}
```

### migrate.py

```json
{
  "fortigate_host": "192.168.1.1",
  "from_interface": "port1",
  "to_interface": "port2",
  "dry_run": false,
  "created_at": "2024-01-15T10:30:00Z",
  "completed_at": "2024-01-15T10:30:05Z",
  "overall_status": "success",
  "total_vlans": 3,
  "successful": 3,
  "failed": 0,
  "steps": [
    {
      "vlan_name": "vlan100",
      "vlan_id": 100,
      "from_interface": "port1",
      "to_interface": "port2",
      "status": "success",
      "error": null,
      "references_affected": {
        "firewall_policies": ["1", "5"]
      },
      "started_at": "2024-01-15T10:30:01Z",
      "completed_at": "2024-01-15T10:30:02Z"
    }
  ],
  "error": null
}
```

### verify.py

```json
{
  "fortigate_host": "192.168.1.1",
  "expected_interface": "port2",
  "timestamp": "2024-01-15T10:35:00Z",
  "overall_status": "pass",
  "summary": {
    "vlans_verified": 3,
    "total_checks": 21,
    "pass": 18,
    "fail": 0,
    "warn": 3
  },
  "vlans": [
    {
      "vlan_name": "vlan100",
      "vlan_id": 100,
      "expected_interface": "port2",
      "overall_status": "pass",
      "summary": {
        "total": 7,
        "pass": 6,
        "fail": 0,
        "warn": 1
      },
      "checks": [
        {
          "name": "vlan_exists",
          "description": "VLAN interface exists",
          "status": "pass",
          "expected": "exists",
          "actual": "exists",
          "message": "VLAN vlan100 found"
        }
      ]
    }
  ],
  "error": null
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error or failure |
| 1 | Warnings (with `--strict`) |

## Error Handling

The toolkit handles these error conditions:

- **Authentication failures**: Invalid or expired API token
- **Connection errors**: Network issues, timeout, unreachable host
- **Not found**: Interface or VLAN doesn't exist
- **Rate limiting**: Automatic retry with exponential backoff
- **VLAN conflicts**: VLAN ID already exists on target interface

## Security Considerations

1. **API Token Storage**: Never commit API tokens to version control
2. **SSL Verification**: Enable in production (`FORTIGATE_VERIFY_SSL=true`)
3. **Network Access**: Restrict API access to management network
4. **Audit Logging**: FortiGate logs all API operations
5. **Backup**: Always backup configuration before migration

## Troubleshooting

### Connection refused

```
FortiGateConnectionError: Connection failed
```

- Verify FortiGate IP/hostname is correct
- Ensure REST API is enabled (System > Feature Visibility)
- Check firewall rules allow API access

### Authentication failed

```
FortiGateAuthError: Authentication failed. Check API key.
```

- Verify API token is correct
- Check token hasn't expired
- Ensure admin profile has required permissions

### VLAN not found

```
FortiGateNotFoundError: Interface 'vlan999' not found
```

- Verify VLAN name (case-sensitive)
- Check VLAN exists on the specified interface

### Rate limit exceeded

```
FortiGateRateLimitError: Rate limit exceeded
```

- Increase `FORTIGATE_RATE_LIMIT` value
- Wait and retry

## License

MIT License - See LICENSE file for details.
