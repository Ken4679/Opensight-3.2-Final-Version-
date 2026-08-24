from __future__ import annotations

import json
import subprocess
import sys
import time
from enum import Enum
from pathlib import Path
from typing import Callable, Optional, Sequence

from opensight.core.safety import is_reparse_point_or_symlink, PortablePaths
from opensight.core.models import RoutingRule

class RoutingState(str, Enum):
    DISABLED = "未启用"
    RUNNING = "分流运行中"
    FAILED = "启动失败"
    ROLLED_BACK = "已停止"

def verify_split_dns_policy(rules: Sequence[RoutingRule], config_doc: dict) -> tuple[bool, str]:
    """
    严格校验应用分流与 Split-DNS 策略一致性：
    1. 每个启用的应用在 route 和 dns 规则中必须且只能唯一匹配 1 条规则。
    2. VPN 应用必须绑定到 vpn-out 与 vpn-dns。
    3. DIRECT 应用必须绑定到 direct-out 与 direct-dns。
    4. 严禁 VPN 应用发生 direct-dns 回退。
    """
    route_rules = config_doc.get("route", {}).get("rules", [])
    dns_rules = config_doc.get("dns", {}).get("rules", [])

    for r in rules:
        if not r.is_enabled:
            continue
        exe = str(r.executable_path).strip()
        matched_route = [item for item in route_rules if exe in item.get("process_path", [])]
        matched_dns = [item for item in dns_rules if exe in item.get("process_path", [])]

        if len(matched_route) != 1 or len(matched_dns) != 1:
            return False, f"应用 '{r.app_name}' 必须且只能匹配 1 条 route/dns 规则 (当前分别匹配到 {len(matched_route)}/{len(matched_dns)} 条)"

        r_item = matched_route[0]
        d_item = matched_dns[0]

        if r.action == "VPN":
            if r_item.get("outbound") != "vpn-out":
                return False, f"VPN 应用 '{r.app_name}' 未正确绑定到 vpn-out 出口"
            if d_item.get("server") != "vpn-dns":
                return False, f"VPN 应用 '{r.app_name}' 未正确绑定到 vpn-dns 解析器"
        elif r.action == "DIRECT":
            if r_item.get("outbound") != "direct-out":
                return False, f"DIRECT 应用 '{r.app_name}' 未正确绑定到 direct-out 出口"
            if d_item.get("server") != "direct-dns":
                return False, f"DIRECT 应用 '{r.app_name}' 未正确绑定到 direct-dns 解析器"

    return True, "Split DNS 策略校验完全一致"

class SingBoxRoutingBackend:
    def __init__(self, portable_paths: PortablePaths):
        self._paths = portable_paths
        self._state = RoutingState.DISABLED
        self._launcher: Optional[subprocess.Popen] = None
        self._routing_dir = portable_paths.data_dir / "routing"
        self._routing_dir.mkdir(parents=True, exist_ok=True)
        self._pid_path = self._routing_dir / "singbox.pid"
        self._stop_path = self._routing_dir / "singbox.stop"
        self._cb = None

    def get_state(self) -> str:
        return self._state.value

    def is_running(self) -> bool:
        pid = self._read_pid()
        if not pid:
            return self._state == RoutingState.RUNNING and self._launcher is not None and self._launcher.poll() is None
        try:
            output = subprocess.check_output(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2.0,
            )
            return str(pid) in output
        except Exception:
            return self._state == RoutingState.RUNNING

    def detect_runtime(self):
        for candidate in (
            self._paths.singbox_dir / "sing-box.exe",
            self._paths.singbox_dir / "sing-box",
            self._paths.base_dir / "sing-box.exe",
            self._paths.base_dir / "sing-box",
        ):
            if candidate.exists() and candidate.is_file() and not is_reparse_point_or_symlink(candidate):
                return type("Runtime", (), {"is_valid": True, "executable_path": candidate, "status_text": "组件就绪"})()
        return type("Runtime", (), {"is_valid": False, "executable_path": None, "status_text": "未检测到 sing-box 核心"})()

    def start_routing(
        self,
        rules: list[RoutingRule],
        direct_dns: list[str],
        vpn_dns: list[str],
        direct_interface: Optional[str],
        vpn_interface: Optional[str],
        on_state_change: Optional[Callable[[str, str], None]] = None,
    ) -> bool:
        self._cb = on_state_change
        if sys.platform != "win32":
            self._set_state(RoutingState.FAILED, "应用分流需要 Windows")
            return False
        if self.is_running():
            self._set_state(RoutingState.RUNNING, "应用分流已经在运行")
            return True

        rt = self.detect_runtime()
        if not rt.is_valid:
            self._set_state(RoutingState.FAILED, "未找到 sing-box 核心")
            return False
        if not vpn_interface:
            self._set_state(RoutingState.FAILED, "未检测到 OpenVPN 虚拟网卡")
            return False

        config_path = self._generate_config(
            rules,
            direct_dns or ["1.1.1.1"],
            vpn_dns or ["1.1.1.1"],
            direct_interface,
            vpn_interface,
        )
        helper = self._paths.base_dir / "run_singbox_windows.ps1"
        if not helper.is_file():
            self._set_state(RoutingState.FAILED, "缺少 TUN 启动工具")
            return False

        self._stop_path.unlink(missing_ok=True)
        self._pid_path.unlink(missing_ok=True)
        try:
            self._launcher = subprocess.Popen(
                [
                    "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-File", str(helper),
                    "-SingBox", str(rt.executable_path),
                    "-Config", str(config_path),
                    "-PidFile", str(self._pid_path),
                    "-StopFile", str(self._stop_path),
                ],
                cwd=str(self._paths.base_dir),
                shell=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            for _ in range(20):
                time.sleep(0.15)
                if self._pid_path.exists():
                    break
                if self._launcher.poll() is not None:
                    break
            if not self._pid_path.exists():
                self._set_state(RoutingState.FAILED, "TUN 启动没有获得管理员权限，或核心启动失败")
                return False
            self._set_state(RoutingState.RUNNING, "应用分流已启动，直连应用走本地 ISP DNS")
            return True
        except Exception as exc:
            self.rollback()
            self._set_state(RoutingState.FAILED, f"分流启动失败：{exc}")
            return False

    def stop_routing(self) -> bool:
        if self._pid_path.exists():
            self._stop_path.write_text("stop", encoding="utf-8")
            for _ in range(20):
                if not self.is_running():
                    break
                time.sleep(0.15)
        if self._launcher:
            try:
                self._launcher.wait(timeout=2.0)
            except Exception:
                pass
            self._launcher = None
        return self.rollback()

    def rollback(self) -> bool:
        try:
            self._stop_path.unlink(missing_ok=True)
            self._pid_path.unlink(missing_ok=True)
            for f in self._routing_dir.glob("config_*.json"):
                f.unlink(missing_ok=True)
            self._set_state(RoutingState.ROLLED_BACK, "分流已停止，网络恢复正常")
            return True
        except Exception:
            return False

    def _read_pid(self) -> Optional[int]:
        try:
            return int(self._pid_path.read_text(encoding="utf-8").strip())
        except Exception:
            return None

    def _generate_config(
        self,
        rules: list[RoutingRule],
        direct_dns: list[str],
        vpn_dns: list[str],
        direct_interface: Optional[str],
        vpn_interface: str,
    ) -> Path:
        route_rules = [{
            "process_path": [str(self._paths.base_dir / "OpenSight.exe")],
            "action": "route",
            "outbound": "direct-out",
        }]
        dns_rules = []

        for rule in rules:
            if not rule.is_enabled:
                continue
            exe = str(rule.executable_path).strip()
            if rule.action == "VPN":
                route_rules.append({"process_path": [exe], "action": "route", "outbound": "vpn-out"})
                dns_rules.append({"process_path": [exe], "action": "route", "server": "vpn-dns"})
            else:
                route_rules.append({"process_path": [exe], "action": "route", "outbound": "direct-out"})
                dns_rules.append({"process_path": [exe], "action": "route", "server": "direct-dns"})

        outbounds = [
            {"type": "direct", "tag": "direct-out", **({"bind_interface": direct_interface} if direct_interface else {})},
            {"type": "direct", "tag": "vpn-out", "bind_interface": vpn_interface},
            {"type": "dns", "tag": "dns-out"},
        ]

        vpn_target = vpn_dns[0] if (vpn_dns and vpn_dns[0] != "1.1.1.1") else "https://dns.google/resolve"
        is_ip_dns = (":" not in vpn_target and not vpn_target.startswith("http"))

        dns_servers = [
            {"type": "local", "tag": "direct-dns", "detour": "direct-out"},
            {
                "type": "udp" if is_ip_dns else "https",
                "tag": "vpn-dns",
                "server": vpn_target if is_ip_dns else "dns.google",
                "detour": "vpn-out",
            },
        ]

        doc = {
            "log": {"level": "warn", "timestamp": True},
            "dns": {
                "servers": dns_servers,
                "rules": dns_rules,
                "final": "direct-dns",
                "strategy": "prefer_ipv4",
            },
            "route": {
                "auto_detect_interface": True,
                "find_process": True,
                "rules": route_rules,
                "final": "direct-out",
            },
            "inbounds": [{
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "OpenSight-TUN",
                "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                "mtu": 1500,
                "auto_route": True,
                "strict_route": True,
                "stack": "system",
            }],
            "outbounds": outbounds,
        }

        # 写入前执行安全策略强校验
        valid, msg = verify_split_dns_policy(rules, doc)
        if not valid:
            raise ValueError(f"Split-DNS 策略校验未通过: {msg}")

        path = self._routing_dir / f"config_{int(time.time())}.json"
        path.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def _set_state(self, st: RoutingState, msg: str):
        self._state = st
        if self._cb:
            self._cb(st.value, msg)
