import time
import threading
from typing import Optional, List
from opensight.core.constants import *
from opensight.core.models import LogicalNode, NodeRecommendation
from opensight.core.scoring import ScoringEngine
from opensight.core.database import Repository

class RecommendationEngine:
    def __init__(self, repository: Repository):
        self._repo = repository
        self._cache_lock = threading.Lock()
        self._cached_evaluations: Optional[List[NodeRecommendation]] = None
        self._cache_timestamp: float = 0.0
        self._cache_ttl_sec: float = 1.5

    def invalidate_cache(self) -> None:
        with self._cache_lock:
            self._cached_evaluations = None
            self._cache_timestamp = 0.0

    def evaluate_node(self, node: LogicalNode) -> NodeRecommendation:
        endpoints = self._repo.get_endpoints_for_node(node.node_id)
        if not endpoints:
            return NodeRecommendation(
                node.node_id, node.server_name, node.country, node.country_code, node.city,
                node.is_free_tier, 0.0, 0.0, 0.0, 0.0, CONFIDENCE_INSUFFICIENT, False, None,
                0, 0, None, None, "tcp", 443, None, CATEGORY_INSUFFICIENT_DATA, "尚未测速", SCORING_VERSION
            )

        evals = []
        history = self._repo.get_measurement_history_for_node(node.node_id, 10)
        for ep in endpoints:
            latest = self._repo.get_latest_measurement_for_endpoint(ep.endpoint_id)
            evals.append((ep, ScoringEngine.evaluate_endpoint(latest, history), latest))

        reachable = [item for item in evals if item[1].is_reachable]
        if not reachable:
            first_ep = endpoints[0]
            latest_any = evals[0][2]
            return NodeRecommendation(
                node.node_id, node.server_name, node.country, node.country_code, node.city,
                node.is_free_tier, 0.0, 0.0, 0.0, 0.0,
                CONFIDENCE_UNAVAILABLE if latest_any else CONFIDENCE_INSUFFICIENT,
                False, first_ep, len(endpoints), 0, None, None,
                first_ep.protocol, first_ep.port,
                latest_any.measured_at if latest_any else None,
                CATEGORY_UNAVAILABLE, "当前 TCP 不可达", SCORING_VERSION
            )

        best_ep, best_score, best_m = max(
            reachable, key=lambda x: (x[1].overall_score, -(x[1].tcp_latency_ms or 9999.0))
        )

        # 只根据本次 TCP 测量结果描述网络响应，不声称已经测试视频带宽。
        lat = best_score.tcp_latency_ms or 999.0
        jitter = best_score.jitter_ms or 0.0
        stab = best_score.stability_score

        if lat <= 45 and jitter <= 8.0:
            exp = f"响应很快（延迟 {int(lat)}ms，抖动 {int(jitter)}ms）"
        elif lat <= 80:
            exp = f"延迟较低（约 {int(lat)}ms）"
        elif stab >= 85.0:
            exp = f"连接较稳定（稳定度 {int(stab)}）"
        else:
            exp = f"已完成基础测速（延迟约 {int(lat)}ms）"

        return NodeRecommendation(
            node.node_id, node.server_name, node.country, node.country_code, node.city,
            node.is_free_tier, best_score.web_score, best_score.video_score,
            best_score.stability_score, best_score.overall_score, best_score.confidence,
            True, best_ep, len(endpoints), len(reachable), best_score.tcp_latency_ms,
            best_score.jitter_ms, best_ep.protocol, best_ep.port,
            best_m.measured_at if best_m else None, CATEGORY_RECOMMENDED, exp, SCORING_VERSION
        )

    def evaluate_all_nodes(self) -> list[NodeRecommendation]:
        now = time.monotonic()
        with self._cache_lock:
            if self._cached_evaluations is not None and (now - self._cache_timestamp) < self._cache_ttl_sec:
                return list(self._cached_evaluations)

        nodes = self._repo.get_all_nodes()
        results = [self.evaluate_node(n) for n in nodes]
        with self._cache_lock:
            self._cached_evaluations = results
            self._cache_timestamp = now
        return results

    def sort_recommendations(
        self, recs: list[NodeRecommendation], mode: str = VIEW_MODE_RECOMMENDED
    ) -> list[NodeRecommendation]:
        res = list(recs)
        if mode == VIEW_MODE_RECOMMENDED:
            res.sort(key=lambda r: (-r.overall_score, r.best_tcp_latency_ms or 99999, r.server_name))
        elif mode == VIEW_MODE_WEB:
            res.sort(key=lambda r: (-r.web_score, r.best_tcp_latency_ms or 99999, r.server_name))
        elif mode == VIEW_MODE_VIDEO:
            res.sort(key=lambda r: (-r.video_score, r.best_jitter_ms or 99999, r.server_name))
        elif mode == VIEW_MODE_STABILITY:
            res.sort(key=lambda r: (-r.stability_score, -r.overall_score, r.server_name))
        elif mode == VIEW_MODE_LATENCY:
            res.sort(key=lambda r: (0 if r.is_reachable else 1, r.best_tcp_latency_ms or 99999, r.server_name))
        elif mode == VIEW_MODE_COUNTRY:
            res.sort(key=lambda r: (r.country, r.server_name))
        elif mode == VIEW_MODE_NAME:
            res.sort(key=lambda r: (r.server_name, r.country))
        elif mode == VIEW_MODE_RECENT:
            res.sort(key=lambda r: (-(r.last_measured_at or 0), r.server_name))
        return res
