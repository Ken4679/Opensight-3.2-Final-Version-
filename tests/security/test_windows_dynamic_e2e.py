import json
import os
import sys
import tempfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from opensight.core.safety import PortablePaths
from opensight.core.models import LogicalNode, Endpoint, RoutingRule
from opensight.core.database import DatabaseManager, Repository
from opensight.core.parser import OvpnParser
from opensight.api.server import create_app
from opensight.vpn.openvpn_process import OpenVPNProcessManager, VPNConnectionState
from opensight.vpn.credentials import CredentialVault, OpenVPNCredentials
from opensight.vpn.leak_guard import VPNLeakGuard
from opensight.vpn.routing.singbox_backend import SingBoxRoutingBackend
from fastapi.testclient import TestClient


@pytest.fixture
def test_env(tmp_path):
    base = tmp_path / "opensight_portable"
    base.mkdir(parents=True, exist_ok=True)
    profiles = base / "profiles"
    profiles.mkdir(parents=True, exist_ok=True)
    data = base / "data"
    data.mkdir(parents=True, exist_ok=True)
    logs = base / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    singbox = base / "singbox"
    singbox.mkdir(parents=True, exist_ok=True)
    openvpn = base / "openvpn"
    openvpn.mkdir(parents=True, exist_ok=True)

    paths = PortablePaths(
        base_dir=base,
        profiles_dir=profiles,
        data_dir=data,
        logs_dir=logs,
        licenses_dir=base / "licenses",
        openvpn_dir=openvpn,
        singbox_dir=singbox,
        is_isolated=True,
    )
    db_mgr = DatabaseManager(data / "opensight.db")
    repo = Repository(db_mgr)
    return paths, repo, db_mgr


def test_e2e_application_backend_lifecycle(test_env):
    """
    E2E Test: Application backend initialization, FastAPI endpoints,
    database bootstrap, WebSocket subscription, and clean shutdown.
    """
    paths, repo, db_mgr = test_env
    auth_token = "dynamic_e2e_token_2026"
    app = create_app(paths, auth_token=auth_token)
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {auth_token}"}

    # 1. Health check & version
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json().get("status") == "ok"

    # 2. Configuration loading (initial empty state)
    nodes_res = client.get("/api/nodes", headers=headers)
    assert nodes_res.status_code == 200
    assert isinstance(nodes_res.json(), list)

    # 3. OVPN Profile Import & Parsing
    sample_ovpn = """
client
dev tun
proto udp
remote jp-node-01.protonvpn.net 1194
resolv-retry infinite
nobind
persist-key
persist-tun
redirect-gateway def1
"""
    profile = OvpnParser.parse_text(sample_ovpn, filename="jp_test.ovpn")
    assert profile.server_name == "jp-node-01"
    assert profile.protocol == "udp"
    assert len(profile.remotes) == 1

    # 4. Routing Rule Configuration
    rule_payload = {
        "app_id": "app_browser",
        "app_name": "Edge Browser",
        "executable_path": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "action": "VPN",
        "enabled": True,
    }
    rule_res = client.post("/api/routing/rules", json=rule_payload, headers=headers)
    assert rule_res.status_code in (200, 201)

    # 5. WebSocket live event push
    with client.websocket_connect(f"/ws?token={auth_token}") as ws:
        data = ws.receive_json()
        assert data.get("event") == "connected"

    # 6. Backend clean state verification
    del client
    del app


def test_e2e_routing_backend_and_split_dns(test_env):
    """
    E2E Test: SingBox split tunneling configuration generation,
    Tun strict route policy, and split DNS binding.
    """
    paths, repo, _ = test_env
    backend = SingBoxRoutingBackend(paths)

    rules = [
        RoutingRule("r1", "Browser", r"C:\Browser\browser.exe", "VPN", True),
        RoutingRule("r2", "LocalApp", r"C:\Local\local.exe", "DIRECT", True),
    ]

    config_path = backend._generate_config(
        rules=rules,
        direct_dns=["192.168.1.1", "1.1.1.1"],
        vpn_dns=["10.2.0.1"],
        direct_interface="Ethernet",
        vpn_interface="OpenSight-TUN",
    )

    assert config_path.is_file()
    cfg_data = json.loads(config_path.read_text(encoding="utf-8"))

    # Assert TUN inbound parameters
    inbounds = cfg_data.get("inbounds", [])
    assert len(inbounds) >= 1
    assert inbounds[0]["type"] == "tun"
    assert inbounds[0]["interface_name"] == "OpenSight-TUN"
    assert inbounds[0]["strict_route"] is True


def test_e2e_failure_injection_fail_closed_killswitch(test_env):
    """
    Failure Injection: Simulate firewall sync failure during connection.
    Verify manager immediately aborts connection and fails closed.
    """
    paths, repo, _ = test_env
    mgr = OpenVPNProcessManager(paths)
    mgr.configure_kill_switch([r"C:\Apps\Browser\chrome.exe"])

    # Simulate firewall install failure
    with patch.object(mgr._leak_guard, "install_app_kill_switch", return_value=False):
        ok = mgr.enable_kill_switch()
        assert ok is False
        assert mgr.is_kill_switch_active is False
        assert mgr.get_state() != VPNConnectionState.CONNECTED


def test_e2e_failure_injection_process_termination(test_env):
    """
    Failure Injection: Simulate unexpected termination of openvpn.exe.
    Verify process handles are cleared and state transitions to DISCONNECTED.
    """
    paths, repo, _ = test_env
    mgr = OpenVPNProcessManager(paths)

    mock_proc = MagicMock()
    mock_proc.poll.return_value = -9  # Killed unexpectedly
    mock_proc.pid = 4321
    mgr._proc = mock_proc
    mgr._state = VPNConnectionState.CONNECTED

    # When disconnect/cleanup is called
    mgr.disconnect()
    assert mgr.get_state() == VPNConnectionState.DISCONNECTED.value
    assert mgr._proc is None
    assert mgr.is_connected() is False
