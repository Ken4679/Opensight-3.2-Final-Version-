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

def test_health_endpoint_public(temp_paths):
    app = create_app(temp_paths, auth_token="super_secret_token_123")
    client = TestClient(app)
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["version"] == "3.2.0"

def test_protected_endpoints_reject_without_token(temp_paths):
    token = "test_valid_token_256bit_secret"
    app = create_app(temp_paths, auth_token=token)
    client = TestClient(app)

    protected_paths = [
        ("GET", "/api/nodes"),
        ("GET", "/api/nodes/recent"),
        ("GET", "/api/credentials"),
        ("GET", "/api/vpn/status"),
        ("GET", "/api/routing/rules"),
        ("GET", "/api/routing/apps"),
        ("POST", "/api/probe/start"),
        ("POST", "/api/probe/stop"),
        ("POST", "/api/vpn/disconnect"),
    ]

    for method, path in protected_paths:
        if method == "GET":
            res = client.get(path)
        else:
            res = client.post(path)
        assert res.status_code == 401, f"{method} {path} should be 401 without token, got {res.status_code}"

def test_protected_endpoints_reject_wrong_token(temp_paths):
    token = "test_valid_token_256bit_secret"
    app = create_app(temp_paths, auth_token=token)
    client = TestClient(app)

    headers = {"Authorization": "Bearer wrong_token_attempt"}
    res = client.get("/api/nodes", headers=headers)
    assert res.status_code == 401
    assert "未授权访问" in res.json().get("detail", "")

def test_protected_endpoints_reject_malformed_auth_header(temp_paths):
    token = "test_valid_token_256bit_secret"
    app = create_app(temp_paths, auth_token=token)
    client = TestClient(app)

    malformed_headers = [
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": "Token secret123"},
        {"Authorization": ""},
        {"Authorization": "Bearer "},
    ]

    for h in malformed_headers:
        res = client.get("/api/nodes", headers=h)
        assert res.status_code == 401, f"Header {h} should be rejected with 401"

def test_protected_endpoints_accept_valid_token(temp_paths):
    token = "test_valid_token_256bit_secret"
    app = create_app(temp_paths, auth_token=token)
    client = TestClient(app)

    headers = {"Authorization": f"Bearer {token}"}
    res = client.get("/api/nodes", headers=headers)
    assert res.status_code == 200

def test_production_auto_generates_token_when_empty(temp_paths):
    # In production without allow_insecure, empty token should result in an auto-generated secret token
    app = create_app(temp_paths, auth_token="", allow_insecure=False)
    client = TestClient(app)

    # Calling without token must fail with 401
    res = client.get("/api/nodes")
    assert res.status_code == 401

def test_insecure_development_mode(temp_paths):
    # In insecure local development mode, empty token is explicitly permitted for local dev/testing
    app = create_app(temp_paths, auth_token="", allow_insecure=True)
    client = TestClient(app)

    res = client.get("/api/nodes")
    assert res.status_code == 200

def test_websocket_auth(temp_paths):
    token = "ws_test_secret_token"
    app = create_app(temp_paths, auth_token=token)
    client = TestClient(app)

    # Rejection without token query param
    with pytest.raises(Exception):
        with client.websocket_connect("/ws") as ws:
            pass

    # Rejection with wrong token
    with pytest.raises(Exception):
        with client.websocket_connect("/ws?token=wrong") as ws:
            pass

    # Success with correct token
    with client.websocket_connect(f"/ws?token={token}") as ws:
        # Connection established successfully
        assert ws is not None
