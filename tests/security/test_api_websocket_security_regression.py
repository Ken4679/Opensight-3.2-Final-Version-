import json
import pytest
from fastapi.testclient import TestClient
from opensight.core.safety import PortablePaths
from opensight.api.server import create_app


@pytest.fixture
def temp_paths(tmp_path):
    base = tmp_path / "opensight_portable"
    base.mkdir(parents=True, exist_ok=True)
    profiles = base / "profiles"
    profiles.mkdir(parents=True, exist_ok=True)
    data = base / "data"
    data.mkdir(parents=True, exist_ok=True)
    logs = base / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    return PortablePaths(
        base_dir=base,
        profiles_dir=profiles,
        data_dir=data,
        logs_dir=logs,
        licenses_dir=base / "licenses",
        openvpn_dir=base / "openvpn",
        singbox_dir=base / "singbox",
        is_isolated=True,
    )


def test_malformed_json_payloads_rejected_with_422(temp_paths):
    """Ensure malformed JSON payloads return 422 unprocessable entity without 500 crashes."""
    token = "test_token_regression_sec_123"
    app = create_app(temp_paths, auth_token=token)
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Invalid JSON syntax
    res = client.post("/api/credentials", content="NOT_JSON_BODY", headers=headers)
    assert res.status_code == 422 or res.status_code == 400

    # Wrong data types (array instead of object)
    res = client.post("/api/credentials", content="[1, 2, 3]", headers=headers)
    assert res.status_code == 422

    # Unexpected data type for boolean/integer fields
    res = client.post("/api/routing/rules", content=json.dumps({"app_id": 12345, "enabled": "not_a_bool"}), headers=headers)
    assert res.status_code == 422 or res.status_code == 400


def test_oversized_string_requests(temp_paths):
    """Ensure extremely large strings in JSON payloads do not cause memory crashes or stack overflow."""
    token = "test_token_regression_sec_123"
    app = create_app(temp_paths, auth_token=token)
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    huge_username = "A" * (1024 * 1024)  # 1MB string
    res = client.post("/api/credentials", json={"username": huge_username, "password": "safe_password"}, headers=headers)
    # Should either succeed or return 422/400 validation error, but NEVER leak 500 internal crash trace
    assert res.status_code in (200, 400, 422)


def test_auth_boundary_prevents_unauthorized_token_variations(temp_paths):
    """Ensure various token bypass attempts fail with 401."""
    valid_token = "correct_bearer_token_abc"
    app = create_app(temp_paths, auth_token=valid_token)
    client = TestClient(app)

    bypass_attempts = [
        {"Authorization": "Bearer "},
        {"Authorization": "Bearer  "},
        {"Authorization": f"Bearer {valid_token}_extra"},
        {"Authorization": f"bearer {valid_token}"},
        {"Authorization": f"Bearer {valid_token[:-1]}"},
        {"Authorization": "Basic dGVzdDp0ZXN0"},
    ]

    for h in bypass_attempts:
        res = client.get("/api/nodes", headers=h)
        assert res.status_code == 401, f"Header {h} should be rejected with 401"


def test_no_sensitive_exception_leakage_on_database_error(temp_paths):
    """Ensure database errors return clean JSON without exposing SQL or python stack traces."""
    token = "test_token_regression_sec_123"
    app = create_app(temp_paths, auth_token=token)
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}

    # Attempt to delete non-existent rule
    res = client.delete("/api/routing/rules?app_id=non_existent_app_id_999", headers=headers)
    assert res.status_code in (200, 404, 400)
    data = res.json()
    # Check that raw python traceback / SQL error is not leaked in response body
    raw_str = json.dumps(data)
    assert "Traceback (most recent call last)" not in raw_str
    assert "sqlite3.OperationalError" not in raw_str


def test_websocket_rapid_connect_and_disconnect(temp_paths):
    """Ensure rapid websocket connect and disconnect cycles do not leak state or crash."""
    token = "ws_test_token_rapid_sec"
    app = create_app(temp_paths, auth_token=token)
    client = TestClient(app)

    for _ in range(5):
        with client.websocket_connect(f"/ws?token={token}") as ws:
            data = ws.receive_json()
            assert data.get("event") == "connected"


def test_websocket_rejects_unauthorized_token_attempts(temp_paths):
    """Ensure websocket rejects connection attempts with invalid tokens."""
    token = "ws_test_token_rapid_sec"
    app = create_app(temp_paths, auth_token=token)
    client = TestClient(app)

    with pytest.raises(Exception):
        with client.websocket_connect("/ws?token=attacker_token") as ws:
            pass
