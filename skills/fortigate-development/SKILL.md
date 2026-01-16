---
name: fortigate-development
description: TDD workflow for FortiGate toolkit - guides test-first development with proper API mocking patterns
---

# FortiGate Toolkit Development

Use this skill when adding features or fixing bugs in the FortiGate toolkit.

## Workflow

### 1. Understand the API Structure

FortiGate API returns interfaces as **lists of dicts**, not strings:

```python
# CORRECT - what FortiGate actually returns
{"srcintf": [{"name": "port1"}], "dstintf": [{"name": "vlan100"}]}

# WRONG - common assumption
{"srcintf": ["port1"], "dstintf": ["vlan100"]}
```

### 2. Write Test First

Before implementing, create a test in `tests/test_fortigate_client.py`:

```python
def test_your_new_feature(self, mock_client):
    """Describe what this tests."""
    # Arrange - mock the API response with CORRECT structure
    mock_client._session.request.return_value = Mock(
        status_code=200,
        ok=True,
        text='{}',
        json=lambda: {"results": [{"name": "test", "type": "vlan"}]},
    )

    # Act
    result = mock_client.your_new_method()

    # Assert
    assert result == expected_value
```

### 3. Run Tests (Must Fail)

```bash
pytest tests/test_fortigate_client.py::TestYourClass::test_your_new_feature -v
```

The test MUST fail before implementation.

### 4. Implement Minimal Code

Add only enough code to make the test pass. No extras.

### 5. Run Tests Again (Must Pass)

```bash
pytest -v
```

All tests must pass, including existing ones.

### 6. Refactor If Needed

Clean up while keeping tests green.

## Mocking Patterns

### Mock Successful Response

```python
mock_client._session.request.return_value = Mock(
    status_code=200,
    ok=True,
    text='{"results": []}',
    json=lambda: {"results": []},
)
```

### Mock Error Response

```python
mock_client._session.request.return_value = Mock(
    status_code=404,
    ok=False,
    text='{"error": "not found"}',
    json=lambda: {"error": "not found"},
    url="https://test.local/api/v2/test",
)
```

### Mock Sequence (for retry tests)

```python
mock_client._session.request.side_effect = [
    requests.ConnectionError("fail"),  # First attempt
    requests.ConnectionError("fail"),  # Second attempt
    Mock(status_code=200, ...),        # Third succeeds
]
```

## Exception Types

| Exception | HTTP Code | Retried? |
|-----------|-----------|----------|
| `FortiGateAuthError` | 401, 403 | No |
| `FortiGateNotFoundError` | 404 | No |
| `FortiGateRateLimitError` | 429 | Yes (3x) |
| `FortiGateConnectionError` | N/A | Yes (3x) |
| `FortiGateError` | 500+ | No |

## Checklist

Before claiming done:

- [ ] Test written FIRST
- [ ] Test failed before implementation
- [ ] All tests pass after implementation
- [ ] Coverage maintained (80%+)
- [ ] No new exceptions without tests
- [ ] API structures use correct dict format
