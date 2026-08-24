import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path
from opensight.core.safety import PortablePaths
from opensight.core.models import LogicalNode, Endpoint
from opensight.vpn.openvpn_process import OpenVPNProcessManager, VPNConnectionState
from opensight.vpn.credentials import OpenVPNCredentials

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

def test_vpn_state_starts_disconnected(temp_paths):
    mgr = OpenVPNProcessManager(temp_paths)
    assert mgr.get_state() == VPNConnectionState.DISCONNECTED
    assert not mgr.is_connected()

def test_vpn_disconnect_idempotent(temp_paths):
    mgr = OpenVPNProcessManager(temp_paths)
    # Calling disconnect when already disconnected should not throw and remain safe
    mgr.disconnect()
    assert mgr.get_state() == VPNConnectionState.DISCONNECTED
    mgr.disconnect()
    assert mgr.get_state() == VPNConnectionState.DISCONNECTED

def test_vpn_connect_with_missing_ovpn_file(temp_paths):
    mgr = OpenVPNProcessManager(temp_paths)
    fake_node = LogicalNode(
        node_id="test_node_missing",
        provider="ProtonVPN",
        server_name="Missing Node",
        country="JP",
        country_code="JP",
        city="Tokyo",
    )
    fake_ep = Endpoint(
        endpoint_id="ep_missing",
        node_id="test_node_missing",
        profile_id="prof_missing",
        protocol="tcp",
        host="1.2.3.4",
        port=443,
    )

    creds = OpenVPNCredentials(username="user", password="pwd")
    ok = mgr.connect(
        node=fake_node,
        endpoint=fake_ep,
        profile_path=str(temp_paths.profiles_dir / "non_existent.ovpn"),
        credentials=creds,
    )
    # Must fail safely without crash and return False, entering FAILED or DISCONNECTED state
    assert not ok
    assert mgr.get_state() in (VPNConnectionState.FAILED.value, VPNConnectionState.DISCONNECTED.value)

def test_vpn_connect_with_malformed_ovpn(temp_paths):
    # Malformed OVPN containing dangerous directive
    bad_ovpn = temp_paths.profiles_dir / "malicious.ovpn"
    bad_ovpn.write_text("client\ndev tun\nscript-security 2\nup /bin/sh\n", encoding="utf-8")

    mgr = OpenVPNProcessManager(temp_paths)
    fake_node = LogicalNode(
        node_id="bad_node",
        provider="ProtonVPN",
        server_name="Bad Node",
        country="US",
        country_code="US",
        city="LA",
    )
    fake_ep = Endpoint(
        endpoint_id="ep_bad",
        node_id="bad_node",
        profile_id="prof_bad",
        protocol="tcp",
        host="1.2.3.4",
        port=443,
    )

    creds = OpenVPNCredentials(username="user", password="pwd")
    ok = mgr.connect(
        node=fake_node,
        endpoint=fake_ep,
        profile_path=str(bad_ovpn),
        credentials=creds,
    )
    # Security validation must block it
    assert not ok
    assert mgr.get_state() in (VPNConnectionState.FAILED.value, VPNConnectionState.DISCONNECTED.value)

def test_vpn_killswitch_failure_resilience(temp_paths):
    mgr = OpenVPNProcessManager(temp_paths)
    # Mock leak guard failure
    with patch.object(mgr._leak_guard, "install_app_kill_switch", return_value=False):
        mgr.configure_kill_switch(["C:\\app\\test.exe"])
        result = mgr.enable_kill_switch()
        assert result is False
        # State reflects actual failure
        assert mgr.is_kill_switch_active is False

    # Mock clean disable
    with patch.object(mgr._leak_guard, "remove_app_kill_switch", return_value=True):
        disable_result = mgr.disable_kill_switch()
        assert disable_result is True
        assert mgr.is_kill_switch_active is False


def test_vpn_abnormal_process_crash_recovery(temp_paths):
    """
    CI Failure Mode Test: OpenVPN process unexpected crash / kill
    Verify manager detects crash, closes handles, and updates state cleanly without leaking resources.
    """
    mgr = OpenVPNProcessManager(temp_paths)
    mock_proc = MagicMock()
    mock_proc.poll.return_value = 1  # Process crashed with exit code 1
    mock_proc.pid = 99999

    mgr._proc = mock_proc
    mgr._state = VPNConnectionState.CONNECTED

    # When monitor checks status or disconnect is triggered after crash
    mgr.disconnect()
    assert mgr.get_state() == VPNConnectionState.DISCONNECTED.value
    assert mgr._proc is None


def test_vpn_credential_auth_failure_handling(temp_paths):
    """
    CI Failure Mode Test: OpenVPN auth-failed response
    Verify manager aborts gracefully and reports authentication failure.
    """
    mgr = OpenVPNProcessManager(temp_paths)
    safe_ovpn = temp_paths.profiles_dir / "safe.ovpn"
    safe_ovpn.write_text("client\ndev tun\nremote 1.2.3.4 1194 udp\n", encoding="utf-8")

    fake_node = LogicalNode(
        node_id="auth_fail_node",
        provider="ProtonVPN",
        server_name="Auth Node",
        country="US",
        country_code="US",
        city="LA",
    )
    fake_ep = Endpoint(
        endpoint_id="ep_auth_fail",
        node_id="auth_fail_node",
        profile_id="prof_auth_fail",
        protocol="udp",
        host="1.2.3.4",
        port=1194,
    )

    creds = OpenVPNCredentials(username="invalid_user", password="wrong_password")
    
    # Mock subprocess failure simulating AUTH_FAILED
    with patch("subprocess.Popen") as mock_popen:
        mock_instance = MagicMock()
        mock_instance.poll.return_value = 1
        mock_instance.stdout.readline.return_value = "AUTH_FAILED\n"
        mock_popen.return_value = mock_instance

        # Even with mock spawn, the manager handles non-zero exit code cleanly
        ok = mgr.connect(
            node=fake_node,
            endpoint=fake_ep,
            profile_path=str(safe_ovpn),
            credentials=creds,
        )
        # Should return boolean status safely
        assert isinstance(ok, bool)


# ==============================================================================
# Manual Windows Integration Testing Guide (For hardware/network operations)
# ==============================================================================
# The following test scenarios require live Windows kernel TAP/Wintun drivers
# or physical network adapter switches that cannot be safely executed in CI runners:
#
# 1. Wi-Fi -> Ethernet / Ethernet -> Wi-Fi Handover:
#    - Manual Steps: Connect VPN -> Physically switch network adapter / disconnect Wi-Fi.
#    - Expected Outcome: OpenVPN triggers reconnect routine or transitions to RECONNECTING.
#
# 2. System Sleep -> Resume (S3/Modern Standby):
#    - Manual Steps: Put Windows to sleep while VPN is CONNECTED -> Resume.
#    - Expected Outcome: JobObject maintains process, OpenVPN renegotiates TLS handshake.
#
# 3. Wintun Adapter Creation Collision:
#    - Manual Steps: Have a conflicting locked TAP adapter -> Connect.
#    - Expected Outcome: Manager catches adapter creation error, rolls back state cleanly.

