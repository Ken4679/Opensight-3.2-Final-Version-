from dataclasses import dataclass, field
import hashlib
import time
from typing import Optional, Literal

ProtocolType = Literal["tcp", "udp"]

@dataclass(frozen=True)
class ParsedRemote:
    host: str
    port: int
    protocol: ProtocolType

    @property
    def normalized_host(self) -> str:
        return self.host.strip().lower()

@dataclass(frozen=True)
class ParsedProfile:
    profile_id: str
    filename: str
    relative_path: str
    file_sha256: str
    file_size_bytes: int
    provider: str
    server_name: str
    country: str
    country_code: str
    city: str
    is_free_tier: bool
    remotes: tuple[ParsedRemote, ...]
    primary_protocol: ProtocolType
    is_tcp: bool
    warnings: tuple[str, ...] = field(default_factory=tuple)

@dataclass(frozen=True)
class ProfileMetadata:
    profile_id: str
    filename: str
    relative_path: str
    file_sha256: str
    file_size_bytes: int
    provider: str = "ProtonVPN"
    imported_at: int = field(default_factory=lambda: int(time.time()))
    updated_at: int = field(default_factory=lambda: int(time.time()))

@dataclass(frozen=True)
class LogicalNode:
    node_id: str
    provider: str
    server_name: str
    country: str
    country_code: str
    city: str
    is_free_tier: bool = True
    created_at: int = field(default_factory=lambda: int(time.time()))
    updated_at: int = field(default_factory=lambda: int(time.time()))

    @staticmethod
    def normalize_server_name(name: str) -> str:
        return name.strip().upper()

    @staticmethod
    def compute_id(provider: str, country_code: str, city: str, server_name: str) -> str:
        sname = LogicalNode.normalize_server_name(server_name)
        token = f"{provider.strip().lower()}:{country_code.strip().upper()}:{city.strip().lower()}:{sname}"
        return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]

@dataclass(frozen=True)
class Endpoint:
    endpoint_id: str
    node_id: str
    profile_id: str
    protocol: ProtocolType
    host: str
    port: int
    ip_resolved: Optional[str] = None
    is_active: bool = True
    last_measured_at: Optional[int] = None

    @staticmethod
    def normalize_host(host: str) -> str:
        return host.strip().lower().rstrip(".")

    @staticmethod
    def compute_id(node_id: str, protocol: str, host: str, port: int) -> str:
        token = f"{node_id.strip().lower()}:{protocol.strip().lower()}:{Endpoint.normalize_host(host)}:{int(port)}"
        return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]

@dataclass(frozen=True)
class MeasurementRecord:
    measurement_id: str
    endpoint_id: str
    node_id: str
    measured_at: int
    is_reachable: bool
    dns_latency_ms: Optional[float] = None
    tcp_latency_ms: Optional[float] = None
    direct_https_latency_ms: Optional[float] = None
    packet_loss_pct: float = 0.0
    jitter_ms: float = 0.0
    error_message: Optional[str] = None
    web_score: float = 0.0
    video_score: float = 0.0
    stability_score: float = 0.0
    overall_score: float = 0.0

    @staticmethod
    def compute_id(endpoint_id: str, timestamp: int) -> str:
        token = f"{endpoint_id.strip().lower()}:{int(timestamp)}"
        return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]

@dataclass(frozen=True)
class ProbePlan:
    endpoint: Endpoint
    sample_count: int = 3
    dns_timeout: float = 2.5
    tcp_timeout: float = 3.5
    https_timeout: float = 4.0
    measure_baseline_https: bool = True

@dataclass(frozen=True)
class EndpointProbeResult:
    endpoint_id: str
    node_id: str
    measured_at: int
    is_reachable: bool
    dns_latency_ms: Optional[float]
    resolved_ip: Optional[str]
    tcp_samples_ms: tuple[float, ...]
    tcp_p50_ms: Optional[float]
    tcp_jitter_ms: Optional[float]
    tcp_success_count: int
    tcp_total_count: int
    tcp_failure_rate_pct: float
    direct_https_latency_ms: Optional[float]
    error_code: str
    error_detail: Optional[str] = None
    cancelled: bool = False

    def to_measurement_record(
        self, web_score: float = 0.0, video_score: float = 0.0, stability_score: float = 0.0, overall_score: float = 0.0
    ) -> MeasurementRecord:
        return MeasurementRecord(
            measurement_id=MeasurementRecord.compute_id(self.endpoint_id, self.measured_at),
            endpoint_id=self.endpoint_id,
            node_id=self.node_id,
            measured_at=self.measured_at,
            is_reachable=self.is_reachable,
            dns_latency_ms=self.dns_latency_ms,
            tcp_latency_ms=self.tcp_p50_ms,
            direct_https_latency_ms=self.direct_https_latency_ms,
            packet_loss_pct=self.tcp_failure_rate_pct,
            jitter_ms=self.tcp_jitter_ms or 0.0,
            error_message=self.error_detail if not self.is_reachable else None,
            web_score=web_score,
            video_score=video_score,
            stability_score=stability_score,
            overall_score=overall_score,
        )

@dataclass(frozen=True)
class ProbeProgress:
    total: int
    completed: int
    successful: int
    failed: int
    pending: int
    current_node_name: str
    current_endpoint_host: str
    current_stage: str
    percentage: float
    is_paused: bool = False
    is_stopped: bool = False

@dataclass(frozen=True)
class EndpointScore:
    endpoint_id: str
    node_id: str
    web_score: float
    video_score: float
    stability_score: float
    overall_score: float
    confidence: str
    is_reachable: bool
    tcp_latency_ms: Optional[float]
    tcp_failure_rate_pct: float
    jitter_ms: Optional[float]
    historical_sample_count: int
    scoring_version: str

@dataclass(frozen=True)
class NodeRecommendation:
    node_id: str
    server_name: str
    country: str
    country_code: str
    city: str
    is_free_tier: bool
    web_score: float
    video_score: float
    stability_score: float
    overall_score: float
    confidence: str
    is_reachable: bool
    best_endpoint: Optional[Endpoint]
    total_endpoints_count: int
    reachable_endpoints_count: int
    best_tcp_latency_ms: Optional[float]
    best_jitter_ms: Optional[float]
    primary_protocol: str
    primary_port: int
    last_measured_at: Optional[int]
    category_tag: str
    explanation: str
    scoring_version: str

@dataclass(frozen=True)
class RoutingRule:
    rule_id: str
    app_name: str
    executable_path: str
    action: Literal["VPN", "DIRECT"]
    is_enabled: bool = True
    created_at: int = field(default_factory=lambda: int(time.time()))
