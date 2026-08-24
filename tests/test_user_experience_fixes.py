from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8-sig")


def test_repair_uses_local_msi_without_download():
    s = read("scripts/repair_openvpn_windows.ps1")
    assert "Invoke-WebRequest" not in s
    assert "LOCAL_MSI_MISSING" in s


def test_video_label_is_honest():
    s = read("src/opensight/core/recommendation.py")
    assert "4K/8K" not in s


def test_probe_stealth_controls():
    c = read("src/opensight/core/constants.py")
    e = read("src/opensight/core/probe_engine.py")
    assert "PROBE_COOLDOWN_JITTER_SEC" in c and "PROBE_FAILURE_BACKOFF_CAP_SEC" in c
    assert "random.uniform(-PROBE_COOLDOWN_JITTER_SEC, PROBE_COOLDOWN_JITTER_SEC)" in e


def test_public_ip_dynamic_order():
    c = read("src/opensight/core/constants.py")
    p = read("src/opensight/core/public_ip.py")
    assert "myip.ipip.net" in c and "set_vpn_connected" in p


def test_api_mode_and_driver_status():
    s = read("src/opensight/api/server.py")
    t = read("web/src/types/index.ts")
    assert 'mode: str = "global"' in s and 'driverReady' in s and 'driverReady?: boolean' in t


def test_recent_nodes_persistence_and_prop():
    db = read("src/opensight/core/database.py")
    api = read("src/opensight/api/server.py")
    app = read("web/src/App.tsx")
    nodelist = read("web/src/components/NodeList.tsx")
    assert "get_recent_nodes" in db and "set_recent_nodes" in db
    assert "/api/nodes/recent" in api
    assert "recentNodeIds={recentNodeIds}" in app
    assert "safeRecentIds" in nodelist


def test_uninstall_script_path_escaping():
    s = read("scripts/uninstall_opensight_windows.ps1")
    assert "escapedBundleRoot" in s
