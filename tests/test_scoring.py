from opensight.core.scoring import ScoringEngine

def test_scoring_clamping():
    assert ScoringEngine.normalize_latency(20.0) >= 95.0
    assert ScoringEngine.normalize_latency(999.0) == 0.0
    assert ScoringEngine.normalize_failure_rate(0.0) == 100.0
    assert ScoringEngine.normalize_failure_rate(100.0) == 0.0