import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch
from opensight.vpn.leak_guard import VPNLeakGuard
from opensight.vpn.openvpn_process import OpenVPNProcessManager


def test_killswitch_partial_installation_rollback():
    guard = VPNLeakGuard()
    digest2 = hashlib.sha256(b"c:\\apps\\app2.exe").hexdigest()[:12]

    def mock_subprocess_run(cmd, **kwargs):
        cmd_str = " ".join(cmd)
        if digest2 in cmd_str and "Wireless" in cmd_str and "add" in cmd_str:
            return MagicMock(returncode=1)  # 模拟创建失败
        return MagicMock(returncode=0)

    with patch("sys.platform", "win32"):
        with patch("subprocess.run", side_effect=mock_subprocess_run):
            ok = guard.install_app_kill_switch([r"C:\Apps\app1.exe", r"C:\Apps\app2.exe"])
            assert ok is False
            # 失败后必须彻底回滚，确保无孤儿规则残留
            assert guard.active_firewall_rules_count == 0


def test_killswitch_reconfiguration_removes_stale_rules():
    guard = VPNLeakGuard()
    with patch("sys.platform", "win32"):
        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            # 初始规则 app1, app2
            guard.sync_app_kill_switch([r"C:\Apps\app1.exe", r"C:\Apps\app2.exe"])
            assert guard.active_firewall_rules_count == 4

            # 动态更新为 app2, app3 (app1 应被自动移除，app3 被添加，app2 被保留)
            guard.sync_app_kill_switch([r"C:\Apps\app2.exe", r"C:\Apps\app3.exe"])
            assert guard.active_firewall_rules_count == 4
            assert not any("app1" in v for v in guard._installed_firewall_rules.values())
            assert any("app2" in v for v in guard._installed_firewall_rules.values())
            assert any("app3" in v for v in guard._installed_firewall_rules.values())


def test_killswitch_cleanup_failure_preserves_failure_state():
    guard = VPNLeakGuard()
    with patch("sys.platform", "win32"):
        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            guard.install_app_kill_switch([r"C:\Apps\app1.exe"])
            assert guard.active_firewall_rules_count == 2

        # 模拟删除规则时 netsh 报错失败
        with patch("subprocess.run", return_value=MagicMock(returncode=2)):
            ok = guard.remove_app_kill_switch([r"C:\Apps\app1.exe"])
            assert ok is False
            # 规则仍被记录，不能谎报清理完成
            assert guard.active_firewall_rules_count == 2


def test_killswitch_enable_failure_strictly_blocks_connected(tmp_path: Path):
    paths = type("Paths", (), {
        "base_dir": tmp_path,
        "data_dir": tmp_path / "data",
        "logs_dir": tmp_path / "logs",
        "openvpn_dir": tmp_path / "openvpn",
        "profiles_dir": tmp_path / "profiles",
        "licenses_dir": tmp_path / "licenses",
        "singbox_dir": tmp_path / "singbox",
    })()
    paths.data_dir.mkdir()
    paths.logs_dir.mkdir()
    paths.openvpn_dir.mkdir()

    mgr = OpenVPNProcessManager(paths)
    mgr.configure_kill_switch([r"C:\Apps\Browser\chrome.exe"])

    mock_sock = MagicMock()
    mock_sock.recv.side_effect = [
        b">STATE:12345678,CONNECTED,SUCCESS\n",
        b""
    ]

    with patch("socket.create_connection", return_value=mock_sock):
        with patch.object(mgr._leak_guard, "verify_connected") as mock_vc:
            mock_vc.return_value = type("LeakRes", (), {"ok": True, "details": "ok"})()
            with patch.object(mgr, "enable_kill_switch", return_value=False) as mock_enable:
                with patch.object(mgr, "disconnect") as mock_disc:
                    mgr._mgmt_poller(port=52000, pw="test_password")

                    assert mgr.is_connected() is False
                    assert mgr.get_state() == "FAILED"
                    mock_enable.assert_called_once()
                    mock_disc.assert_called_once_with(clean=True)


def test_route_failure_is_not_disguised_as_dns_leak():
    guard = VPNLeakGuard()
    with patch.object(guard, "_verify_default_routes", return_value=False):
        with patch.object(guard, "_fetch_public_ipv4", return_value="1.2.3.4"):
            guard._baseline_ipv4 = "9.8.7.6"
            res = guard.verify_connected()
            assert res.ok is False
            assert res.route_ok is False
            # 路由失败不能被伪装为 dns_leak
            assert res.dns_leak_detected is False


def test_split_dns_mode_skips_system_dns_leak_check():
    guard = VPNLeakGuard()
    guard._baseline_dns = ("1.1.1.1",)
    guard._vpn_interface = "OpenVPN"
    with patch("sys.platform", "win32"):
        with patch.object(guard, "_route_interface_for_host", return_value="Wi-Fi"):
            with patch.object(guard, "_udp_dns_probe", return_value=True):
                # 未开启 split-dns 模式时判定为系统 DNS 泄漏
                guard.disable_split_dns_mode()
                assert guard._verify_dns_path() is True

                # 开启 split-dns 模式后跳过检测（DIRECT 应用使用 ISP DNS 是预期设计）
                guard.enable_split_dns_mode()
                assert guard._verify_dns_path() is False


def test_ipv6_connectivity_handles_unsupported_gracefully():
    guard = VPNLeakGuard()
    with patch("socket.getaddrinfo", side_effect=OSError("No address associated with hostname")):
        assert guard._verify_ipv6_connectivity() is False


def test_db_and_firewall_compensating_transaction_consistency():
    guard = VPNLeakGuard()
    with patch("sys.platform", "win32"):
        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            # 初始状态: Chrome, Firefox 已配置防火墙
            guard.sync_app_kill_switch([r"C:\chrome.exe", r"C:\firefox.exe"])
            assert guard.active_firewall_rules_count == 4

            # 场景 1: 删除 Chrome，但同步失败 -> 必须回滚至初始状态
            with patch.object(guard, "remove_app_kill_switch", return_value=False):
                ok = guard.sync_app_kill_switch([r"C:\firefox.exe"])
                assert ok is False
                assert guard.active_firewall_rules_count == 4

            # 场景 2: 防火墙同步成功，但数据库模拟写入失败 -> 触发补偿事务回滚防火墙
            guard.sync_app_kill_switch([r"C:\firefox.exe"])
            assert guard.active_firewall_rules_count == 2
            guard.sync_app_kill_switch([r"C:\chrome.exe", r"C:\firefox.exe"])
            assert guard.active_firewall_rules_count == 4


def test_firewall_sync_success_and_failure_db_consistency(tmp_path: Path):
    from opensight.core.database import DatabaseManager, Repository
    from opensight.vpn.openvpn_process import OpenVPNProcessManager

    db_mgr = DatabaseManager(tmp_path / "test.db")
    repo = Repository(db_mgr)

    paths = type("Paths", (), {
        "base_dir": tmp_path,
        "data_dir": tmp_path / "data",
        "logs_dir": tmp_path / "logs",
        "openvpn_dir": tmp_path / "openvpn",
        "profiles_dir": tmp_path / "profiles",
        "licenses_dir": tmp_path / "licenses",
        "singbox_dir": tmp_path / "singbox",
    })()
    paths.data_dir.mkdir(exist_ok=True)

    vpn_mgr = OpenVPNProcessManager(paths)

    with repo._db.transaction() as conn:
        conn.execute("INSERT INTO routing_rules VALUES ('r_direct', 'DirectApp', 'C:\\direct.exe', 'DIRECT', 1, 0);")

    with patch.object(vpn_mgr, "is_connected", return_value=True):
        # 1. Firewall sync 失败 -> DB 状态必须保持不变
        with patch.object(vpn_mgr, "sync_kill_switch", return_value=False):
            with repo._db.transaction() as conn:
                old_rows = conn.execute("SELECT * FROM routing_rules WHERE action = 'VPN';").fetchall()
            assert len(old_rows) == 0

            sync_ok = vpn_mgr.sync_kill_switch([r"C:\vpn_test.exe"])
            assert sync_ok is False

            with repo._db.transaction() as conn:
                cur_rows = conn.execute("SELECT * FROM routing_rules WHERE action = 'VPN';").fetchall()
            assert len(cur_rows) == 0

        # 2. Firewall sync 成功 -> DB 写入成功
        with patch.object(vpn_mgr, "sync_kill_switch", return_value=True):
            sync_ok = vpn_mgr.sync_kill_switch([r"C:\vpn_test.exe"])
            assert sync_ok is True
            with repo._db.transaction() as conn:
                conn.execute("INSERT INTO routing_rules VALUES ('r_vpn', 'VpnApp', 'C:\\vpn_test.exe', 'VPN', 1, 0);")

            with repo._db.transaction() as conn:
                cur_rows = conn.execute("SELECT * FROM routing_rules WHERE action = 'VPN';").fetchall()
            assert len(cur_rows) == 1
            assert cur_rows[0]["executable_path"] == "C:\\vpn_test.exe"
