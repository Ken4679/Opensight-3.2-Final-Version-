import asyncio
import http.client
import ipaddress
import socket
import random
import time
import urllib.parse
import httpx
from statistics import median
from typing import Callable, Optional, List
from opensight.core.constants import (
    DEFAULT_PROBE_CONCURRENCY, DEFAULT_BASELINE_HTTPS_TARGETS,
    SUCCESS_COOLDOWN_SEC, FAILURE_COOLDOWN_SEC, PROBE_COOLDOWN_JITTER_SEC,
    PROBE_FAILURE_BACKOFF_CAP_SEC, PROBE_WORKER_START_JITTER_SEC, STAGE_CHECKING_IP, STAGE_TCP_PROBING,
    STAGE_COMPLETED, STAGE_STOPPED, ERR_NONE, ERR_DNS_TIMEOUT, ERR_DNS_FAILED,
    ERR_TCP_TIMEOUT, ERR_TCP_REFUSED, ERR_TCP_NETWORK_ERROR, ERR_CANCELLED,
    ERR_IP_DRIFT_DETECTED
)
from opensight.core.models import Endpoint, LogicalNode, ProbePlan, EndpointProbeResult, ProbeProgress
from opensight.core.public_ip import PublicIPGuard
from opensight.core.database import Repository

class SafeProbeEngine:
    def __init__(
        self,
        repository: Repository,
        concurrency: int = DEFAULT_PROBE_CONCURRENCY,
        baseline_targets: tuple = DEFAULT_BASELINE_HTTPS_TARGETS,
        ip_guard: Optional[PublicIPGuard] = None,
    ):
        self._repo = repository
        self._concurrency = max(1, min(concurrency, 8))
        self._baseline_targets = [t for t in baseline_targets if urllib.parse.urlparse(t).scheme == "https"]
        self._ip_guard = ip_guard or PublicIPGuard()
        self._pause_event = asyncio.Event()
        self._pause_event.set()
        self._stop_event = asyncio.Event()
        self._failure_streaks: dict[str, int] = {}

    def pause(self):
        self._pause_event.clear()

    def resume(self):
        self._pause_event.set()

    def stop(self):
        self._stop_event.set()
        self._pause_event.set()

    @property
    def is_paused(self):
        return not self._pause_event.is_set()

    @property
    def is_stopped(self):
        return self._stop_event.is_set()

    async def run_batch(
        self,
        nodes: List[LogicalNode],
        on_progress: Optional[Callable[[ProbeProgress], None]] = None,
        force_refresh: bool = False,
    ) -> List[EndpointProbeResult]:
        self._stop_event.clear()
        self._pause_event.set()
        now = int(time.time())

        plans = []
        for n in nodes:
            for ep in self._repo.get_endpoints_for_node(n.node_id):
                if not force_refresh and self._is_cooldown(ep, now):
                    continue
                plans.append((n, ProbePlan(ep)))

        total = len(plans)
        if total == 0:
            return []

        if on_progress:
            on_progress(ProbeProgress(total, 0, 0, 0, total, "公网 IP 校验", "-", STAGE_CHECKING_IP, 0.0))

        await self._ip_guard.record_baseline()
        baseline_ms = await self._measure_baseline()

        queue = asyncio.Queue()
        for item in plans:
            queue.put_nowait(item)

        results = []
        lock = asyncio.Lock()
        completed = successful = failed = 0

        async def worker():
            nonlocal completed, successful, failed
            while not self._stop_event.is_set():
                await self._pause_event.wait()
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    if queue.empty():
                        break
                    continue
                if self._stop_event.is_set() or item is None:
                    queue.task_done()
                    break

                n, plan = item
                await asyncio.sleep(random.uniform(0.0, PROBE_WORKER_START_JITTER_SEC))
                valid, _ = await self._ip_guard.check_periodic_drift()
                if not valid:
                    self.stop()
                    queue.task_done()
                    break

                if on_progress and not self._stop_event.is_set():
                    progress_item = ProbeProgress(
                        total, completed, successful, failed, total - completed,
                        n.server_name, plan.endpoint.host, STAGE_TCP_PROBING,
                        round((completed / total) * 100, 1), self.is_paused, self.is_stopped,
                    )
                    on_progress(progress_item)

                res = await self._probe_endpoint(plan, baseline_ms)
                async with lock:
                    results.append(res)
                    self._repo.record_measurement(res.to_measurement_record())
                    self._repo.set_endpoint_ip(res.endpoint_id, res.resolved_ip)
                    completed += 1
                    if res.is_reachable:
                        successful += 1
                        self._failure_streaks[res.endpoint_id] = 0
                    else:
                        failed += 1
                        self._failure_streaks[res.endpoint_id] = self._failure_streaks.get(res.endpoint_id, 0) + 1
                queue.task_done()

        tasks = [asyncio.create_task(worker()) for _ in range(self._concurrency)]
        await asyncio.gather(*tasks, return_exceptions=True)

        # 严格校验 IP 完整性并形成门禁判断
        intact, _ = await self._ip_guard.verify_integrity()
        if not intact:
            for i, r in enumerate(results):
                if r.is_reachable:
                    results[i] = EndpointProbeResult(
                        r.endpoint_id, r.node_id, r.measured_at, False, r.dns_latency_ms,
                        r.resolved_ip, r.tcp_samples_ms, r.tcp_p50_ms, r.tcp_jitter_ms,
                        0, r.tcp_total_count, 100.0, r.direct_https_latency_ms,
                        ERR_IP_DRIFT_DETECTED, "检测到网络环境发生异常公网 IP 偏移",
                    )

        if on_progress:
            final_progress = ProbeProgress(
                total, completed, successful, failed, total - completed,
                "完成" if not self.is_stopped else "已停止", "-",
                STAGE_COMPLETED if not self.is_stopped else STAGE_STOPPED,
                100.0 if not self.is_stopped else round((completed / total) * 100, 1),
                False, self.is_stopped,
            )
            on_progress(final_progress)
        return results

    async def _probe_endpoint(self, plan: ProbePlan, baseline_ms: Optional[float]) -> EndpointProbeResult:
        ep = plan.endpoint
        now = int(time.time())
        if self._stop_event.is_set():
            return EndpointProbeResult(
                ep.endpoint_id, ep.node_id, now, False, None, None,
                (), None, None, 0, plan.sample_count, 100.0, baseline_ms, ERR_CANCELLED, cancelled=True,
            )

        dns_ms, ip, dns_err = await self._measure_dns(ep.host, plan.dns_timeout)
        if dns_err:
            return EndpointProbeResult(
                ep.endpoint_id, ep.node_id, now, False, None, None,
                (), None, None, 0, plan.sample_count, 100.0, baseline_ms, dns_err,
            )

        target = ip or ep.host
        samples = []
        tcp_err = ERR_NONE
        for _ in range(plan.sample_count):
            if self._stop_event.is_set():
                break
            s_ms, err = await self._measure_tcp(target, ep.port, plan.tcp_timeout)
            if s_ms is not None:
                samples.append(s_ms)
            else:
                tcp_err = err

        succ = len(samples)
        fail_pct = ((plan.sample_count - succ) / plan.sample_count) * 100.0
        p50 = round(median(samples), 2) if succ > 0 else None
        jitter = round(
            sum(abs(samples[i] - samples[i - 1]) for i in range(1, len(samples))) / (len(samples) - 1), 2
        ) if len(samples) >= 2 else None

        return EndpointProbeResult(
            ep.endpoint_id, ep.node_id, now, succ > 0, round(dns_ms, 2) if dns_ms else None, ip,
            tuple(samples), p50, jitter, succ, plan.sample_count, round(fail_pct, 1),
            baseline_ms, ERR_NONE if succ > 0 else tcp_err,
        )

    async def _measure_dns(self, host: str, timeout: float):
        clean_host = host.strip("[]").rstrip(".")
        try:
            parsed = ipaddress.ip_address(clean_host)
            return 0.0, str(parsed), None
        except ValueError:
            pass

        doh_servers = (
            "https://dns.alidns.com/resolve",
            "https://cloudflare-dns.com/dns-query",
            "https://dns.google/resolve",
            "https://dns.quad9.net/dns-query",
        )
        had_timeout = False
        start = time.perf_counter()

        for doh_url in doh_servers:
            try:
                request_timeout = httpx.Timeout(timeout, connect=timeout, read=timeout, write=timeout, pool=timeout)
                async with httpx.AsyncClient(timeout=request_timeout, follow_redirects=False, trust_env=False) as client:
                    response = await client.get(
                        doh_url, params={"name": clean_host, "type": "A"}, headers={"Accept": "application/dns-json"}
                    )
                if response.status_code != 200:
                    continue
                payload = response.json()
                for answer in payload.get("Answer") or []:
                    if int(answer.get("type", 0)) != 1:
                        continue
                    answer_data = str(answer.get("data", "")).strip()
                    try:
                        ipv4 = ipaddress.ip_address(answer_data)
                        if ipv4.version == 4:
                            return (time.perf_counter() - start) * 1000.0, str(ipv4), None
                    except ValueError:
                        continue
            except httpx.TimeoutException:
                had_timeout = True
            except Exception:
                continue

        loop = asyncio.get_running_loop()
        fallback_start = time.perf_counter()
        try:
            res = await asyncio.wait_for(
                loop.getaddrinfo(clean_host, None, family=socket.AF_INET, type=socket.SOCK_STREAM), timeout
            )
            for item in res:
                sockaddr = item[4]
                if sockaddr and ipaddress.ip_address(sockaddr[0]).version == 4:
                    return (time.perf_counter() - fallback_start) * 1000.0, sockaddr[0], None
            return None, None, ERR_DNS_FAILED
        except asyncio.TimeoutError:
            return None, None, ERR_DNS_TIMEOUT
        except OSError:
            return None, None, ERR_DNS_TIMEOUT if had_timeout else ERR_DNS_FAILED
        except Exception:
            return None, None, ERR_DNS_FAILED

    async def _measure_tcp(self, host: str, port: int, timeout: float):
        start = time.perf_counter()
        writer = None
        try:
            target = ipaddress.ip_address(host.strip("[]"))
            if target.version != 4:
                return None, ERR_TCP_NETWORK_ERROR
        except ValueError:
            return None, ERR_TCP_NETWORK_ERROR
        try:
            r, writer = await asyncio.wait_for(asyncio.open_connection(str(target), port), timeout)
            return (time.perf_counter() - start) * 1000.0, ERR_NONE
        except asyncio.TimeoutError:
            return None, ERR_TCP_TIMEOUT
        except ConnectionRefusedError:
            return None, ERR_TCP_REFUSED
        except OSError:
            return None, ERR_TCP_NETWORK_ERROR
        finally:
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    async def _measure_baseline(self) -> Optional[float]:
        for t in self._baseline_targets:
            try:
                p = urllib.parse.urlparse(t)
                start = time.perf_counter()
                conn = http.client.HTTPSConnection(p.netloc, timeout=4.0)
                conn.request("HEAD", p.path or "/", headers={"User-Agent": "OpenSight/3.1"})
                if conn.getresponse().status in (200, 204, 301, 302):
                    conn.close()
                    return round((time.perf_counter() - start) * 1000.0, 2)
            except Exception:
                continue
        return None

    def _is_cooldown(self, ep: Endpoint, now: int) -> bool:
        m = self._repo.get_latest_measurement_for_endpoint(ep.endpoint_id)
        if not m:
            return False
        if m.is_reachable:
            cooldown = float(SUCCESS_COOLDOWN_SEC)
        else:
            failures = self._failure_streaks.get(ep.endpoint_id, 0)
            cooldown = min(float(PROBE_FAILURE_BACKOFF_CAP_SEC), float(FAILURE_COOLDOWN_SEC) * (2 ** max(0, failures)))
        cooldown += random.uniform(-PROBE_COOLDOWN_JITTER_SEC, PROBE_COOLDOWN_JITTER_SEC)
        return (now - m.measured_at) < max(5.0, cooldown)
