import json
from pathlib import Path

from opensight.core.models import RoutingRule
from opensight.vpn.routing.singbox_backend import SingBoxRoutingBackend, verify_split_dns_policy

def test_split_dns_and_tun_config(tmp_path: Path):
    paths = type("Paths", (), {
        "base_dir": tmp_path,
        "data_dir": tmp_path / "data",
        "singbox_dir": tmp_path / "singbox",
    })()
    paths.data_dir.mkdir()
    paths.singbox_dir.mkdir()
    backend = SingBoxRoutingBackend(paths)
    rules = [
        RoutingRule("vpn1", "浏览器", r"C:\Program Files\Browser\browser.exe", "VPN", True),
        RoutingRule("direct1", "下载器", r"C:\Apps\Downloader\download.exe", "DIRECT", True),
    ]
    config = backend._generate_config(
        rules,
        ["192.168.1.1"],
        ["10.2.0.1"],
        "Wi-Fi",
        "OpenVPN",
    )
    doc = json.loads(config.read_text(encoding="utf-8"))
    assert doc["inbounds"][0]["type"] == "tun"
    assert doc["inbounds"][0]["interface_name"] == "OpenSight-TUN"
    assert doc["inbounds"][0]["strict_route"] is True
    assert any(
        r.get("process_path") == [r"C:\Program Files\Browser\browser.exe"] and r.get("outbound") == "vpn-out"
        for r in doc["route"]["rules"]
    )
    assert any(
        r.get("process_path") == [r"C:\Apps\Downloader\download.exe"] and r.get("outbound") == "direct-out"
        for r in doc["route"]["rules"]
    )
    assert any(
        r.get("process_path") == [r"C:\Apps\Downloader\download.exe"] and r.get("server") == "direct-dns"
        for r in doc["dns"]["rules"]
    )
    assert any(
        r.get("process_path") == [r"C:\Program Files\Browser\browser.exe"] and r.get("server") == "vpn-dns"
        for r in doc["dns"]["rules"]
    )

def test_verify_split_dns_policy_enforcement():
    rules = [
        RoutingRule("vpn1", "VPN App", r"C:\App\vpn.exe", "VPN", True),
        RoutingRule("direct1", "Direct App", r"C:\App\direct.exe", "DIRECT", True),
    ]
    valid_doc = {
        "route": {"rules": [
            {"process_path": [r"C:\App\vpn.exe"], "outbound": "vpn-out"},
            {"process_path": [r"C:\App\direct.exe"], "outbound": "direct-out"},
        ]},
        "dns": {"rules": [
            {"process_path": [r"C:\App\vpn.exe"], "server": "vpn-dns"},
            {"process_path": [r"C:\App\direct.exe"], "server": "direct-dns"},
        ]}
    }
    ok, msg = verify_split_dns_policy(rules, valid_doc)
    assert ok is True

    # 校验 VPN 应用发生 direct-dns 回退时立即被拦截
    bad_doc = {
        "route": {"rules": [
            {"process_path": [r"C:\App\vpn.exe"], "outbound": "vpn-out"},
            {"process_path": [r"C:\App\direct.exe"], "outbound": "direct-out"},
        ]},
        "dns": {"rules": [
            {"process_path": [r"C:\App\vpn.exe"], "server": "direct-dns"},
            {"process_path": [r"C:\App\direct.exe"], "server": "direct-dns"},
        ]}
    }
    ok, msg = verify_split_dns_policy(rules, bad_doc)
    assert ok is False
    assert "vpn-dns" in msg

def test_verify_split_dns_policy_multiple_match_rejection():
    rules = [
        RoutingRule("vpn1", "VPN App", r"C:\App\vpn.exe", "VPN", True),
    ]
    # 构造同一个 vpn.exe 匹配了多条 route 规则（冲突配置）
    multi_route_doc = {
        "route": {"rules": [
            {"process_path": [r"C:\App\vpn.exe"], "outbound": "vpn-out"},
            {"process_path": [r"C:\App\vpn.exe"], "outbound": "direct-out"},
        ]},
        "dns": {"rules": [
            {"process_path": [r"C:\App\vpn.exe"], "server": "vpn-dns"},
        ]}
    }
    ok, msg = verify_split_dns_policy(rules, multi_route_doc)
    assert ok is False
    assert "必须且只能匹配" in msg

def test_app_selector_is_safe_on_non_windows():
    from opensight.vpn.routing.app_selector import AppSelector
    assert AppSelector.validate_executable("", "").is_valid is False
