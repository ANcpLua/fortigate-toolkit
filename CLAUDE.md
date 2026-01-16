# CLAUDE.md

> Claude Code instructions for the FortiGate Toolkit

## What This Is

A production-ready Python toolkit for FortiGate firewall automation:

- **fortigate_client.py** - API client with rate limiting, retry logic, error handling
- **discover.py** - Discover VLANs and their dependencies
- **migrate.py** - Plan and execute VLAN migrations between interfaces
- **verify.py** - Verify VLAN configurations post-migration

## Quick Start

```bash
# Setup
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

# Run tests
pytest

# Set environment for real FortiGate
export FORTIGATE_HOST="firewall.example.com"
export FORTIGATE_API_KEY="your-api-token"
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    FortiGate API                        │
└─────────────────────────┬───────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│              FortiGateClient (fortigate_client.py)      │
│  • Rate limiting (1 req/sec default)                    │
│  • Retry with exponential backoff (connection + 429)    │
│  • Specific exception types                             │
└─────────────────────────┬───────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
┌───────▼───────┐ ┌───────▼───────┐ ┌───────▼───────┐
│  discover.py  │ │  migrate.py   │ │  verify.py    │
│  Find VLANs   │ │  Move VLANs   │ │  Check VLANs  │
└───────────────┘ └───────────────┘ └───────────────┘
```

## Key Patterns

### Error Handling

```python
from fortigate_client import (
    FortiGateClient,
    FortiGateAuthError,      # 401/403
    FortiGateNotFoundError,  # 404
    FortiGateRateLimitError, # 429 (auto-retried)
    FortiGateConnectionError,# Connection issues (auto-retried)
    FortiGateError,          # Base exception
)
```

### Retry Behavior

The client automatically retries on:
- `FortiGateConnectionError` - network issues
- `FortiGateRateLimitError` - 429 responses

With exponential backoff: 2s → 4s → 8s (max 3 attempts)

### FortiGate API Structure

**Important:** FortiGate API returns interfaces as objects, not strings:

```python
# API returns this:
{"srcintf": [{"name": "port1"}], "dstintf": [{"name": "vlan100"}]}

# NOT this:
{"srcintf": ["port1"], "dstintf": ["vlan100"]}
```

## Testing

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=fortigate_client --cov-report=html

# Run specific test class
pytest tests/test_fortigate_client.py::TestRetryBehavior -v
```

### Test Categories

| Class | Tests |
|-------|-------|
| `TestRateLimiter` | Rate limiting behavior |
| `TestClientInitialization` | Client setup, env vars |
| `TestErrorHandling` | HTTP error → exception mapping |
| `TestRetryBehavior` | Retry on transient failures |
| `TestVlanReferences` | VLAN dependency detection |
| `TestVlanOperations` | CRUD operations |

## Working on This Codebase

### Before Making Changes

1. Run existing tests: `pytest`
2. Understand the retry decorator in `fortigate_client.py:189-194`
3. Check API response structures in `tests/conftest.py` fixtures

### Adding Features

1. Write test first (TDD)
2. Use existing exception types
3. Respect rate limiting
4. Add fixtures for new API responses

### Common Gotchas

1. **Interface lists are dicts** - Always extract `.get("name")` from interface lists
2. **Retry catches wrapped exceptions** - Don't catch `requests.ConnectionError` directly
3. **Rate limiter state** - Each client instance has its own rate limiter

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FORTIGATE_HOST` | Yes | - | Firewall hostname/IP |
| `FORTIGATE_API_KEY` | Yes | - | REST API token |
| `FORTIGATE_VERIFY_SSL` | No | `false` | SSL verification |
| `FORTIGATE_TIMEOUT` | No | `30` | Request timeout (sec) |
| `FORTIGATE_RATE_LIMIT` | No | `1.0` | Min seconds between requests |

## File Structure

```
fortigate-toolkit/
├── CLAUDE.md              # This file
├── README.md              # User documentation
├── fortigate_client.py    # Core API client
├── discover.py            # VLAN discovery
├── migrate.py             # Migration planning/execution
├── verify.py              # Post-migration verification
├── requirements.txt       # Runtime dependencies
├── requirements-dev.txt   # Test dependencies
├── pytest.ini             # Test configuration
└── tests/
    ├── __init__.py
    ├── conftest.py        # Shared fixtures
    └── test_fortigate_client.py
```
