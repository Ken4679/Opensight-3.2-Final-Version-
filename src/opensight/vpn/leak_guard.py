from __future__ import annotations



import hashlib
import ntpath

import ipaddress

import json

import socket

import ssl

import subprocess

import sys

import time

from dataclasses import dataclass

from pathlib import Path

from typing import Dict, Optional, Sequence

from opensight.core.public_ip import PublicIPGuard

from opensight.core.logger import get_logger





@dataclass(frozen=True)

class LeakCheckResult:

    ok: bool

    public_ip_changed: bool

    dns_leak_detected: bool

    ipv6_leak_detected: bool

    route_ok: bool

    details: str





class VPNLeakGuard:

    def __init__(self, timeout: float = 3.0):

        self._timeout = timeout

        self._logger = get_logger("leak_guard")

        self._baseline_dns: tuple[str, ...] = ()

        self._baseline_ipv4: Optional[str] = None

        self._baseline_interface: Optional[str] = None

        self._current_ipv4: Optional[str] = None

        self._current_dns: tuple[str, ...] = ()

        self._vpn_interface: Optional[str] = None

        self._split_dns_mode_enabled = False
        self._split_tunnel_mode = False
        self._public_ip_guard = PublicIPGuard()

        # 跟踪已安装规则: rule_name -> executable_path

        self._installed_firewall_rules: Dict[str, str] = {}



    @property

    def baseline_dns(self) -> tuple[str, ...]:

        return self._baseline_dns



    @property

    def baseline_ipv4(self) -> Optional[str]:

        return self._baseline_ipv4



    @property

    def current_ipv4(self) -> Optional[str]:

        return self._current_ipv4



    @property

    def current_dns(self) -> tuple[str, ...]:

        return self._current_dns



    @property

    def baseline_interface(self) -> Optional[str]:

        return self._baseline_interface



    @property

    def vpn_interface(self) -> Optional[str]:

        return self._vpn_interface



    @property

    def active_firewall_rules_count(self) -> int:

        return len(self._installed_firewall_rules)



    def enable_split_dns_mode(self) -> None:

        """启用应用级分流模式，在此模式下 DIRECT 应用走物理网卡/ISP DNS 是预期设计"""

        self._split_dns_mode_enabled = True



    def disable_split_dns_mode(self) -> None:

        """关闭应用级分流模式，恢复标准全局 DNS 泄漏检测"""

        self._split_dns_mode_enabled = False



    def set_split_tunnel_mode(self, enabled: bool) -> None:
        self._split_tunnel_mode = bool(enabled)

    @property
    def split_tunnel_mode(self) -> bool:
        return self._split_tunnel_mode

    def build_openvpn_security_args(self) -> list[str]:
        if not self._is_windows():
            return ["--route-nopull"] if self._split_tunnel_mode else ["--redirect-gateway", "def1", "block-local"]
        if self._split_tunnel_mode:
            return ["--route-nopull", "--block-ipv6"]
        return ["--redirect-gateway", "def1", "block-local", "ipv6", "--block-ipv6"]




    def capture_baseline(self, public_ip: Optional[str] = None) -> None:

        self._baseline_dns = self._get_dns_servers()

        self._baseline_ipv4 = public_ip or self._fetch_public_ipv4()

        self._baseline_interface = self._get_default_interface()

        self._logger.info(

            "Leak protection baseline captured: dns=%s ipv4=%s",

            self._baseline_dns,

            self._baseline_ipv4,

        )



    def set_vpn_interface(self, alias: Optional[str]) -> None:

        self._vpn_interface = alias



    def verify_connected(self) -> LeakCheckResult:
        self._vpn_interface = self._detect_vpn_interface()
        self._public_ip_guard.set_vpn_connected(bool(self._vpn_interface))
        current_ip = self._public_ip_guard_sync_fetch()
        self._current_ipv4 = current_ip
        self._current_dns = self._get_dns_servers()
        public_ip_changed = bool(self._baseline_ipv4 and current_ip and current_ip != self._baseline_ipv4)
        route_ok = self._verify_default_routes()
        dns_leak = self._verify_dns_path()
        ipv6_leak = self._verify_ipv6_connectivity()
        ok = bool(route_ok and not dns_leak and not ipv6_leak and (public_ip_changed if not self._split_tunnel_mode else True))
        details = (
            f"public_ip={self._baseline_ipv4}->{current_ip}; "
            f"dns_leak={dns_leak}; ipv6_leak={ipv6_leak}; route_ok={route_ok}; "
            f"vpn_if={self._vpn_interface or '-'}; mode={'split' if self._split_tunnel_mode else 'global'}"
        )
        return LeakCheckResult(ok, public_ip_changed, dns_leak, ipv6_leak, route_ok, details)




    def _detect_vpn_interface(self) -> Optional[str]:
        if not self._is_windows():
            return None
        try:
            if self._split_tunnel_mode:
                ps_cmd = "@(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.Name -match 'OpenVPN|TAP|TUN' } | Select-Object -ExpandProperty Name)[0]"
            else:
                ps_cmd = (
                    "$r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/1','128.0.0.0/1' "
                    "-ErrorAction SilentlyContinue | Sort-Object RouteMetric,ifMetric; "
                    "if($r){$i=$r[0].ifIndex; "
                    "(Get-NetIPInterface -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceAlias}"
                )
            out = subprocess.check_output(["powershell.exe", "-NoProfile", "-Command", ps_cmd], text=True, stderr=subprocess.DEVNULL, timeout=8).strip()
            return out.splitlines()[0].strip() if out else None
        except Exception as exc:
            self._logger.warning("Could not detect VPN interface: %s", exc)
            return None

    def _public_ip_guard_sync_fetch(self) -> Optional[str]:
        import asyncio
        try:
            return asyncio.run(self._public_ip_guard.fetch_current_ip())
        except Exception:
            return self._fetch_public_ipv4()




    def _verify_default_routes(self) -> bool:

        if self._split_tunnel_mode:
            return bool(self._vpn_interface)


        if not self._is_windows() or not self._vpn_interface:

            return False

        try:

            escaped_iface = self._vpn_interface.replace("'", "''")

            ps_cmd = (

                "$r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/1','128.0.0.0/1' "

                "-ErrorAction SilentlyContinue; if(-not $r){exit 1}; "

                "$aliases=@($r | ForEach-Object { (Get-NetIPInterface -InterfaceIndex $_.ifIndex "

                "-AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceAlias }); "

                f"if($aliases -contains '{escaped_iface}'){{exit 0}}; exit 1"

            )

            cmd = ["powershell.exe", "-NoProfile", "-Command", ps_cmd]

            return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8).returncode == 0

        except Exception as exc:

            self._logger.warning("IPv4 VPN route check failed: %s", exc)

            return False



    def _verify_dns_path(self) -> bool:

        # 分流模式下 DIRECT 应用走本地 ISP DNS 是预期设计，跳过系统级 DNS 检测

        if self._split_dns_mode_enabled:

            return False

        if not self._is_windows() or not self._baseline_dns:

            return False

        for dns in self._baseline_dns:

            try:

                ip = ipaddress.ip_address(dns)

            except ValueError:

                continue

            if ip.version != 4:

                continue

            route_if = self._route_interface_for_host(dns)

            if route_if and self._vpn_interface and route_if.lower() != self._vpn_interface.lower():

                if self._udp_dns_probe(dns):

                    return True

        return False



    def _verify_ipv6_connectivity(self) -> bool:

        try:

            infos = socket.getaddrinfo("api6.ipify.org", 443, socket.AF_INET6, socket.SOCK_STREAM)

            if not infos:

                return False

            family, socktype, proto, _, sockaddr = infos[0]

            with socket.socket(family, socktype, proto) as sock:

                sock.settimeout(self._timeout)

                sock.connect(sockaddr)

                request = b"GET / HTTP/1.1\r\nHost: api6.ipify.org\r\nConnection: close\r\n\r\n"

                sock.sendall(request)

                data = sock.recv(1024)

                return bool(data)

        except Exception:

            return False



    def _route_interface_for_host(self, host: str) -> Optional[str]:

        if not self._is_windows():

            return None

        try:

            ps_cmd = (

                f"$r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '{host}/32' -ErrorAction SilentlyContinue | "

                "Sort-Object RouteMetric,ifMetric | Select-Object -First 1; "

                "if($r){(Get-NetIPInterface -InterfaceIndex $r.ifIndex -AddressFamily IPv4).InterfaceAlias}"

            )

            cmd = ["powershell.exe", "-NoProfile", "-Command", ps_cmd]

            out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=5).strip()

            return out.splitlines()[0].strip() if out else None

        except Exception:

            return None



    def _udp_dns_probe(self, dns_server: str) -> bool:

        try:

            txid = int(time.time() * 1000) & 0xFFFF

            qname = b"\x07example\x03com\x00"

            packet = txid.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:

                sock.settimeout(1.2)

                sock.sendto(packet, (dns_server, 53))

                data, _ = sock.recvfrom(1024)

                return len(data) >= 12 and int.from_bytes(data[:2], "big") == txid

        except Exception:

            return False



    def _get_default_interface(self) -> Optional[str]:

        if not self._is_windows():

            return None

        try:

            ps_cmd = (

                "$r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "

                "Sort-Object RouteMetric,ifMetric | Select-Object -First 1; "

                "if($r){(Get-NetIPInterface -InterfaceIndex $r.ifIndex "

                "-AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceAlias}"

            )

            cmd = ["powershell.exe", "-NoProfile", "-Command", ps_cmd]

            out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=8).strip()

            return out.splitlines()[0].strip() if out else None

        except Exception:

            return None



    def _get_dns_servers(self) -> tuple[str, ...]:

        if not self._is_windows():

            return ()

        try:

            cmd = [

                "powershell.exe", "-NoProfile", "-Command",

                "Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 | "

                "ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | "

                "Sort-Object -Unique | ConvertTo-Json -Compress"

            ]

            out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=8).strip()

            if not out:

                return ()

            data = json.loads(out)

            if isinstance(data, str):

                return (data,)

            return tuple(str(x) for x in data if x)

        except Exception as exc:

            self._logger.warning("Could not capture Windows DNS servers: %s", exc)

            return ()



    def install_app_kill_switch(self, program_paths: Sequence[str]) -> bool:

        """

        具备严格事务原子性的 KillSwitch 安装机制：

        若有任何一条规则创建失败，立即回滚清理本批次已创建的全部规则，确保无孤儿规则残留。

        """

        if not self._is_windows():

            return True

        newly_installed: Dict[str, str] = {}

        for program in sorted(set(program_paths)):

            try:

                exe = ntpath.normpath(str(program))
                if not ntpath.isabs(exe):
                    exe = ntpath.abspath(exe)

            except Exception:

                continue

            if not exe.lower().endswith(".exe"):

                continue

            digest = hashlib.sha256(exe.lower().encode("utf-8")).hexdigest()[:12]

            for iface in ("LAN", "Wireless"):

                name = f"OpenSight-KillSwitch-{digest}-{iface}"

                if name in self._installed_firewall_rules:

                    continue

                res = subprocess.run([

                    "netsh", "advfirewall", "firewall", "add", "rule",

                    f"name={name}", "dir=out", "action=block",

                    f"program={exe}", f"interfaceType={iface}", "profile=any", "enable=yes"

                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

                if res.returncode == 0:

                    newly_installed[name] = exe

                else:

                    self._logger.error("KillSwitch 规则安装失败: %s (代码: %d)，执行回滚...", name, res.returncode)

                    for rollback_name in newly_installed:

                        subprocess.run([

                            "netsh", "advfirewall", "firewall", "delete", "rule", f"name={rollback_name}"

                        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

                    return False

        self._installed_firewall_rules.update(newly_installed)

        return True



    def remove_app_kill_switch(self, program_paths: Sequence[str]) -> bool:

        """

        可靠移除指定的 KillSwitch 规则，仅当被指示的所有规则均成功删除后返回 True。

        """

        if not self._is_windows():

            return True

        target_exes = set(ntpath.normpath(str(p)).lower() for p in program_paths if p)

        success = True

        for name, exe in list(self._installed_firewall_rules.items()):

            if not target_exes or exe.lower() in target_exes:

                res = subprocess.run([

                    "netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"

                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

                if res.returncode in (0, 1):  # 0=已删除, 1=已不存在

                    del self._installed_firewall_rules[name]

                else:

                    self._logger.error("KillSwitch 规则删除失败: %s (代码: %d)", name, res.returncode)

                    success = False

        return success



    def sync_app_kill_switch(self, desired_program_paths: Sequence[str]) -> bool:

        """

        动态规则原子同步：记录快照，自动清除废弃规则、安装新增规则；若任何一步失败则回滚至快照。

        """

        desired = set(ntpath.normpath(str(p)).lower() for p in desired_program_paths if str(p).lower().endswith(".exe"))

        current = set(exe.lower() for exe in self._installed_firewall_rules.values())

        to_remove = current - desired

        to_add = desired - current



        snapshot = dict(self._installed_firewall_rules)



        if to_remove:

            if not self.remove_app_kill_switch(list(to_remove)):

                self._logger.error("KillSwitch 规则清理失败，正在尝试回滚至快照...")

                rollback_ok = self._restore_from_snapshot(snapshot)

                if not rollback_ok:

                    self._logger.critical("KillSwitch 回滚至快照亦失败，系统防火墙状态可能不一致！")

                return False



        if to_add:

            if not self.install_app_kill_switch(list(to_add)):

                self._logger.error("KillSwitch 规则安装失败，正在尝试回滚至快照...")

                rollback_ok = self._restore_from_snapshot(snapshot)

                if not rollback_ok:

                    self._logger.critical("KillSwitch 回滚至快照亦失败，系统防火墙状态可能不一致！")

                return False



        return True



    def _restore_from_snapshot(self, snapshot: Dict[str, str]) -> bool:

        """回滚防火墙状态至指定快照"""

        if not self._is_windows():

            return True

        success = True

        current_names = set(self._installed_firewall_rules.keys())

        snapshot_names = set(snapshot.keys())



        # 删除新创建但不在快照中的规则

        for name in (current_names - snapshot_names):

            res = subprocess.run([

                "netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"

            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

            if res.returncode in (0, 1):

                self._installed_firewall_rules.pop(name, None)

            else:

                self._logger.error("KillSwitch 回滚删除规则失败: %s (代码: %d)", name, res.returncode)

                success = False



        # 重新恢复被删除但存在于快照中的规则

        missing_exes = set(exe for name, exe in snapshot.items() if name not in self._installed_firewall_rules)

        if missing_exes:

            if not self.install_app_kill_switch(list(missing_exes)):

                self._logger.error("KillSwitch 回滚重新安装规则失败: %s", missing_exes)

                success = False



        return success



    def _fetch_public_ipv4(self) -> Optional[str]:

        try:

            with socket.create_connection(("api.ipify.org", 443), timeout=self._timeout) as sock:

                ctx = ssl.create_default_context()

                with ctx.wrap_socket(sock, server_hostname="api.ipify.org") as tls:

                    tls.sendall(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")

                    body = tls.recv(1024).decode("utf-8", errors="ignore")

                    candidate = body.split("\r\n\r\n", 1)[-1].strip()

                    return str(ipaddress.ip_address(candidate))

        except Exception as exc:

            self._logger.warning("Could not determine public IPv4: %s", exc)

            return None



    @staticmethod

    def _is_windows() -> bool:

        return sys.platform == "win32"
