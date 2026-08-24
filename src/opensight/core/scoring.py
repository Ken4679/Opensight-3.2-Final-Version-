import math
from typing import Optional
from opensight.core.constants import *
from opensight.core.models import MeasurementRecord, EndpointScore

class ScoringEngine:
    @staticmethod
    def normalize_latency(latency_ms: Optional[float]) -> float:
        if latency_ms is None or math.isnan(latency_ms) or latency_ms < 0:
            return 0.0
        if latency_ms <= 35:
            return round(100.0 - (latency_ms / 35.0) * 5.0, 2)
        if latency_ms <= 80:
            return round(95.0 - ((latency_ms - 35) / 45.0) * 15.0, 2)
        if latency_ms <= 180:
            return round(80.0 - ((latency_ms - 80) / 100.0) * 20.0, 2)
        if latency_ms <= 350:
            return round(60.0 - ((latency_ms - 180) / 170.0) * 30.0, 2)
        if latency_ms <= 600:
            return round(max(0.0, 30.0 - ((latency_ms - 350) / 250.0) * 30.0), 2)
        return 0.0

    @staticmethod
    def normalize_failure_rate(fail_pct: Optional[float]) -> float:
        if fail_pct is None or math.isnan(fail_pct):
            return 0.0
        return round(max(0.0, min(100.0, 100.0 * (1.0 - (max(0.0, min(fail_pct, 100.0)) / 100.0) ** 1.2))), 2)

    @staticmethod
    def normalize_jitter(jitter_ms: Optional[float]) -> float:
        if jitter_ms is None or math.isnan(jitter_ms) or jitter_ms < 0:
            return 50.0
        if jitter_ms <= 3:
            return 100.0
        if jitter_ms <= 20:
            return round(100.0 - ((jitter_ms - 3) / 17.0) * 40.0, 2)
        if jitter_ms <= 80:
            return round(max(0.0, 60.0 - ((jitter_ms - 20) / 60.0) * 60.0), 2)
        return 0.0

    @classmethod
    def calculate_web_score(cls, lat: Optional[float], fail: float, jit: Optional[float], reach: bool) -> float:
        if not reach:
            return 0.0
        score = cls.normalize_latency(lat) * 0.50 + cls.normalize_failure_rate(fail) * 0.35 + cls.normalize_jitter(jit) * 0.15
        return round(score, 1)

    @classmethod
    def calculate_video_score(cls, lat: Optional[float], fail: float, jit: Optional[float], reach: bool) -> float:
        if not reach:
            return 0.0
        score = cls.normalize_latency(lat) * 0.40 + cls.normalize_failure_rate(fail) * 0.35 + cls.normalize_jitter(jit) * 0.25
        return round(score, 1)

    @classmethod
    def calculate_stability_score(
        cls, latest: Optional[MeasurementRecord], history: list[MeasurementRecord]
    ) -> tuple[float, str]:
        records = (history or ([latest] if latest else []))[:10]
        if not records:
            return 0.0, CONFIDENCE_INSUFFICIENT
        reach_ratio = sum(1 for r in records if r.is_reachable) / len(records)
        fail_scores = [cls.normalize_failure_rate(r.packet_loss_pct) for r in records if r.is_reachable]
        avg_fail = sum(fail_scores) / len(fail_scores) if fail_scores else 0.0
        lats = [r.tcp_latency_ms for r in records if r.is_reachable and r.tcp_latency_ms is not None]
        if len(lats) == 1:
            var_factor = 0.8
        elif len(lats) >= 2:
            mean_lat = sum(lats) / len(lats)
            std_dev = math.sqrt(sum((x - mean_lat) ** 2 for x in lats) / len(lats))
            var_factor = max(0.0, min(1.0, 1.0 - (std_dev / max(mean_lat, 10.0))))
        else:
            var_factor = 0.0

        score = round(max(0.0, min(reach_ratio * 50.0 + (avg_fail / 100.0) * 30.0 + var_factor * 20.0, 100.0)), 1)
        conf = CONFIDENCE_HIGH if len(records) >= 5 else (CONFIDENCE_MEDIUM if len(records) >= 2 else CONFIDENCE_LOW)
        return score, conf

    @classmethod
    def evaluate_endpoint(cls, latest: Optional[MeasurementRecord], history: list[MeasurementRecord]) -> EndpointScore:
        if not latest:
            return EndpointScore(
                "", "", 0.0, 0.0, 0.0, 0.0, CONFIDENCE_INSUFFICIENT, False,
                None, 100.0, None, 0, SCORING_VERSION
            )
        web = cls.calculate_web_score(
            latest.tcp_latency_ms, latest.packet_loss_pct, latest.jitter_ms, latest.is_reachable
        )
        vid = cls.calculate_video_score(
            latest.tcp_latency_ms, latest.packet_loss_pct, latest.jitter_ms, latest.is_reachable
        )
        stab, conf = cls.calculate_stability_score(latest, history)
        overall = round(web * 0.35 + vid * 0.35 + stab * 0.30, 1) if latest.is_reachable else 0.0
        return EndpointScore(
            latest.endpoint_id, latest.node_id, web, vid, stab, overall, conf,
            latest.is_reachable, latest.tcp_latency_ms, latest.packet_loss_pct,
            latest.jitter_ms, len(history), SCORING_VERSION
        )
