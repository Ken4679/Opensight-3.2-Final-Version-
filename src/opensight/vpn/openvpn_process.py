import os

import secrets

import socket

import subprocess

import threading

import time

from enum import Enum

from pathlib import Path

from typing import Callable, Optional, Sequence

from opensight.core.safety import is_reparse_point_or_symlink, PortablePaths

from opensight.core.logger import CredentialSanitizer, get_logger

from opensight.core.models import LogicalNode, Endpoint

from opensight.core.ovpn_security import validate_ovpn_security

from opensight.vpn.credentials import OpenVPNCredentials

from opensight.vpn.backend_base import VPNBackend

from opensight.vpn.leak_guard import VPNLeakGuard



class VPNConnectionState(str, Enum):

    DISCONNECTED = "DISCONNECTED"

    VALIDATING = "VALIDATING"

    STARTING = "STARTING"

    CONNECTING = "CONNECTING"

    AUTHENTICATING = "AUTHENTICATING"

    CONNECTED = "CONNECTED"

    DISCONNECTING = "DISCONNECTING"

    FAILED = "FAILED"



_CN_MAP = {

    VPNConnectionState.DISCONNECTED: "未连接",

    VPNConnectionState.VALIDATING: "检查配置与安全策略",

    VPNConnectionState.STARTING: "启动核心进程",

    VPNConnectionState.CONNECTING: "建立网络连接",

    VPNConnectionState.AUTHENTICATING: "验证凭据",

    VPNConnectionState.CONNECTED: "VPN 已连接",

    VPNConnectionState.DISCONNECTING: "正在断开",

    VPNConnectionState.FAILED: "连接失败",

}



class OpenVPNProcessManager(VPNBackend):

    def __init__(self, portable_paths: PortablePaths):

        self._paths = portable_paths

        self._logger = get_logger("vpn_process")

        self._sanitizer = CredentialSanitizer.get_instance()

        self._state = VPNConnectionState.DISCONNECTED

        self._proc: Optional[subprocess.Popen] = None

        self._stop_mgmt = threading.Event()

        self._cb = None

        self._leak_guard = VPNLeakGuard()

        self._fail_closed = True

        self._kill_switch_programs: list[str] = []

        self._kill_switch_active = False

        self._mgmt_pw = ""

        self._mgmt_pw_file: Optional[Path] = None



        # 实时流量统计与当前连接节点跟踪

        self._connected_node_id: Optional[str] = None
        self._routing_mode = "global"

        self._last_bytes_in = 0

        self._last_bytes_out = 0

        self._last_calc_time = time.time()

        self._rate_in = 0.0   # B/s (下载)

        self._rate_out = 0.0  # B/s (上传)



    def get_state(self) -> str:

        return self._state.value



    def is_connected(self) -> bool:

        return self._state == VPNConnectionState.CONNECTED



    @property

    def connected_node_id(self) -> Optional[str]:

        return self._connected_node_id if self.is_connected() else None




    @property
    def routing_mode(self) -> str:
        return self._routing_mode

    def refresh_network_snapshot(self) -> None:
        try:
            self._leak_guard.verify_connected()
        except Exception:
            pass

    @property
    def is_kill_switch_active(self) -> bool:

        return self._kill_switch_active



    def get_traffic_rates(self) -> dict:

        """获取当前 VPN 上行/下行速率 (Bytes/s) 与累计字节数"""

        if not self.is_connected():

            return {"uploadSpeedBps": 0, "downloadSpeedBps": 0, "bytesIn": 0, "bytesOut": 0}

        return {

            "uploadSpeedBps": round(self._rate_out, 1),

            "downloadSpeedBps": round(self._rate_in, 1),

            "bytesIn": self._last_bytes_in,

            "bytesOut": self._last_bytes_out,

        }



    def configure_kill_switch(self, program_paths: Sequence[str]) -> None:

        self._kill_switch_programs = list(program_paths)



    def sync_kill_switch(self, program_paths: Sequence[str]) -> bool:

        if self.is_connected() and self._fail_closed:

            ok = self._leak_guard.sync_app_kill_switch(program_paths)

            if ok:

                self._kill_switch_programs = list(program_paths)

            self._kill_switch_active = (self._leak_guard.active_firewall_rules_count > 0)

            return ok

        self._kill_switch_programs = list(program_paths)

        return True



    def enable_kill_switch(self) -> bool:

        if not self._kill_switch_programs:

            self._kill_switch_active = False

            return True

        ok = self._leak_guard.install_app_kill_switch(self._kill_switch_programs)

        self._kill_switch_active = ok

        if not ok:

            self._logger.warning("KillSwitch 防火墙规则未能全部建立！")

        return ok



    def disable_kill_switch(self) -> bool:

        if not self._kill_switch_programs and self._leak_guard.active_firewall_rules_count == 0:

            self._kill_switch_active = False

            return True

        ok = self._leak_guard.remove_app_kill_switch(self._kill_switch_programs)

        # 严格依据防火墙真实清理结果设置状态，避免状态与真实系统脱节

        self._kill_switch_active = (self._leak_guard.active_firewall_rules_count > 0)

        return ok



    def verify_leak_protection(self):

        return self._leak_guard.verify_connected()



    def get_network_snapshot(self) -> dict:

        return {

            "direct_ip": self._leak_guard.baseline_ipv4,

            "vpn_ip": self._leak_guard.current_ipv4,

            "direct_dns": list(self._leak_guard.baseline_dns),

            "vpn_dns": list(self._leak_guard.current_dns),

            "direct_interface": self._leak_guard.baseline_interface,

            "vpn_interface": self._leak_guard.vpn_interface,

        }



    def connect(

        self,

        node: LogicalNode,

        endpoint: Endpoint,

        profile_path: str,

        credentials: Optional[OpenVPNCredentials] = None,

        executable_path: Optional[Path] = None,

        routing_mode: str = "global",

        on_state_change: Optional[Callable[[str, str], None]] = None,

    ) -> bool:

        self._cb = on_state_change
        if routing_mode not in {"global", "split"}:
            self._set_state(VPNConnectionState.FAILED, "无效的连接模式")
            return False
        self._routing_mode = routing_mode
        self._leak_guard.set_split_tunnel_mode(routing_mode == "split")

        if self._proc is not None:

            self._set_state(VPNConnectionState.FAILED, "已有运行中的 VPN 会话")

            return False



        self._connected_node_id = node.node_id

        self._last_bytes_in = 0

        self._last_bytes_out = 0

        self._rate_in = 0.0

        self._rate_out = 0.0

        self._last_calc_time = time.time()



        if not executable_path:

            bundled = self._paths.openvpn_dir / ("openvpn.exe" if os.name == "nt" else "openvpn")

            if bundled.is_file():

                executable_path = bundled



        if not executable_path or not executable_path.is_file() or is_reparse_point_or_symlink(executable_path):

            self._set_state(VPNConnectionState.FAILED, "OpenVPN 可执行文件无效或未找到")

            return False



        self._set_state(VPNConnectionState.VALIDATING, "执行安全策略验证...")

        p_file = Path(profile_path).resolve()

        if not p_file.is_file() or is_reparse_point_or_symlink(p_file):

            self._set_state(VPNConnectionState.FAILED, "配置文件无效")

            return False



        try:

            content = p_file.read_text(encoding="utf-8", errors="ignore")

            is_safe, reason = validate_ovpn_security(content, p_file.name)

            if not is_safe:

                self._set_state(VPNConnectionState.FAILED, f"配置安全拦截: {reason}")

                return False

        except Exception as e:

            self._set_state(VPNConnectionState.FAILED, f"读取配置失败: {e}")

            return False



        if self._fail_closed:

            self._leak_guard.capture_baseline()



        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

            s.bind(("127.0.0.1", 0))

            mgmt_port = s.getsockname()[1]



        self._mgmt_pw = secrets.token_hex(16)

        self._mgmt_pw_file = self._paths.data_dir / f"mgmt_{mgmt_port}.pwd"

        self._mgmt_pw_file.write_text(self._mgmt_pw + "\n", encoding="utf-8")



        args = [

            str(executable_path.resolve()),

            "--config", str(p_file),

            "--management", "127.0.0.1", str(mgmt_port), str(self._mgmt_pw_file),

            "--management-hold",

            "--verb", "3"

        ]

        if credentials and credentials.username and credentials.password:

            args.append("--auth-user-pass")

        if endpoint:

            args.extend(["--remote", endpoint.host, str(endpoint.port), endpoint.protocol])

        args.extend(self._leak_guard.build_openvpn_security_args())



        self._set_state(VPNConnectionState.STARTING, "启动 OpenVPN 核心进程...")

        try:

            self._proc = subprocess.Popen(

                args,

                shell=False,

                stdout=subprocess.PIPE,

                stderr=subprocess.PIPE,

                stdin=subprocess.PIPE if credentials and credentials.username and credentials.password else subprocess.DEVNULL,

                cwd=str(self._paths.base_dir),

                text=True,

                encoding="utf-8",

                errors="replace"

            )

            if credentials and credentials.username and credentials.password and self._proc.stdin is not None:

                self._proc.stdin.write(f"{credentials.username}\n{credentials.password}\n")

                self._proc.stdin.flush()

                self._proc.stdin.close()

            self._stop_mgmt.clear()

            threading.Thread(target=self._mgmt_poller, args=(mgmt_port, self._mgmt_pw), daemon=True).start()

            self._set_state(VPNConnectionState.CONNECTING, "建立网络连接...")

            return True

        except Exception as e:

            self._cleanup()

            self.disable_kill_switch()

            self._set_state(VPNConnectionState.FAILED, f"进程启动异常: {e}")

            return False



    def disconnect(self, clean: bool = True) -> bool:

        if not self._proc:

            self._connected_node_id = None

            if clean:

                self.disable_kill_switch()

                self._leak_guard.disable_split_dns_mode()
                self._leak_guard.set_split_tunnel_mode(False)
                self._routing_mode = "global"

            return True

        self._set_state(VPNConnectionState.DISCONNECTING, "正在安全断开...")

        self._stop_mgmt.set()

        try:

            self._proc.terminate()

            try:

                self._proc.wait(timeout=3.0)

            except subprocess.TimeoutExpired:

                self._proc.kill()

                self._proc.wait(timeout=2.0)

        except Exception:

            pass

        self._cleanup()

        self._connected_node_id = None

        if clean:

            self.disable_kill_switch()

            self._leak_guard.disable_split_dns_mode()
            self._leak_guard.set_split_tunnel_mode(False)
            self._routing_mode = "global"

        self._set_state(VPNConnectionState.DISCONNECTED, "VPN 已安全断开")

        return True



    def _set_state(self, st: VPNConnectionState, msg: str):

        self._state = st

        if st in (VPNConnectionState.DISCONNECTED, VPNConnectionState.FAILED):

            self._connected_node_id = None

            self._rate_in = 0.0

            self._rate_out = 0.0

        if self._cb:

            self._cb(st.value, _CN_MAP.get(st, msg))



    def _cleanup(self):

        if self._proc and self._proc.stdin:

            try:

                self._proc.stdin.close()

            except Exception:

                pass

        self._proc = None

        if self._mgmt_pw_file and self._mgmt_pw_file.exists():

            try:

                self._mgmt_pw_file.unlink(missing_ok=True)

            except Exception:

                pass



    def _mgmt_poller(self, port: int, pw: str):

        time.sleep(0.3)

        sock = None

        try:

            sock = socket.create_connection(("127.0.0.1", port), timeout=3.0)

            sock.sendall(f"{pw}\nhold release\nstate on\nbytecount 1\n".encode("utf-8"))

            buf = ""

            while not self._stop_mgmt.is_set():

                if self._proc and self._proc.poll() is not None:

                    self._set_state(VPNConnectionState.FAILED, f"核心进程退出 (代码: {self._proc.poll()})")

                    self.disable_kill_switch()

                    break

                try:

                    data = sock.recv(1024).decode("utf-8", errors="ignore")

                except socket.timeout:

                    continue

                if not data:

                    break

                buf += data

                while "\n" in buf:

                    line, buf = buf.split("\n", 1)

                    line_str = line.strip()

                    if line_str.startswith(">BYTECOUNT:"):

                        try:

                            parts = line_str.split(":", 1)[1].split(",")

                            if len(parts) >= 2:

                                now = time.time()

                                dt = max(0.2, now - self._last_calc_time)

                                b_in, b_out = int(parts[0]), int(parts[1])

                                if self._last_bytes_in > 0:

                                    self._rate_in = max(0.0, (b_in - self._last_bytes_in) / dt)

                                    self._rate_out = max(0.0, (b_out - self._last_bytes_out) / dt)

                                self._last_bytes_in = b_in

                                self._last_bytes_out = b_out

                                self._last_calc_time = now

                        except Exception:

                            pass

                    elif ">STATE:" in line_str:

                        p = line_str.split(",")

                        if len(p) >= 2:

                            st = p[1].upper()

                            if st == "CONNECTED":

                                if self._fail_closed:

                                    check = self._leak_guard.verify_connected()

                                    if not check.ok:

                                        self._logger.error("VPN 泄漏防护门禁未通过: %s", check.details)

                                        self._set_state(VPNConnectionState.FAILED, "VPN 泄漏防护检查失败，已拒绝进入连接状态")

                                        self.disconnect(clean=False)

                                        return

                                    # 严禁在 KillSwitch 启用失败时进入 CONNECTED 状态

                                    if not self.enable_kill_switch():

                                        self._logger.error("KillSwitch 防火墙规则启用失败，拒绝进入连接状态！")

                                        self._set_state(VPNConnectionState.FAILED, "KillSwitch 启用失败，已拒绝进入连接状态")

                                        self.disconnect(clean=True)

                                        return

                                self._set_state(VPNConnectionState.CONNECTED, "VPN 已连接，泄漏防护检查通过")

                            elif st == "AUTH":

                                self._set_state(VPNConnectionState.AUTHENTICATING, "验证凭据中")

                    elif "AUTH_FAILED" in line_str:

                        self._set_state(VPNConnectionState.FAILED, "凭据验证失败")

                        self.disable_kill_switch()

        except Exception:

            pass

        finally:

            if sock:

                sock.close()
