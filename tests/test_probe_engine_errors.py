import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from opensight.core.constants import (
    ERR_DNS_FAILED,
    ERR_DNS_TIMEOUT,
    ERR_TCP_NETWORK_ERROR,
    ERR_TCP_REFUSED,
    ERR_TCP_TIMEOUT,
)
from opensight.core.probe_engine import SafeProbeEngine

def make_engine() -> SafeProbeEngine:
    return SafeProbeEngine(MagicMock())

def test_measure_dns_timeout():
    async def _run():
        engine = make_engine()
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=httpx.ReadTimeout("timed out")):
            with patch("asyncio.BaseEventLoop.getaddrinfo", new_callable=AsyncMock, side_effect=asyncio.TimeoutError()):
                _, _, error = await engine._measure_dns("timeout.invalid", 0.01)
        assert error == ERR_DNS_TIMEOUT
    asyncio.run(_run())

def test_measure_dns_failed():
    async def _run():
        engine = make_engine()
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=httpx.ConnectError("dns backend down")):
            with patch("asyncio.BaseEventLoop.getaddrinfo", new_callable=AsyncMock, side_effect=OSError("resolver failed")):
                _, _, error = await engine._measure_dns("bad.invalid", 0.01)
        assert error == ERR_DNS_FAILED
    asyncio.run(_run())

def test_measure_tcp_connection_refused():
    async def _run():
        engine = make_engine()
        with patch("asyncio.open_connection", new_callable=AsyncMock, side_effect=ConnectionRefusedError()):
            latency, error = await engine._measure_tcp("127.0.0.1", 443, 0.01)
        assert latency is None
        assert error == ERR_TCP_REFUSED
    asyncio.run(_run())

def test_measure_tcp_timeout_and_network_error():
    async def _run():
        engine = make_engine()
        with patch("asyncio.open_connection", new_callable=AsyncMock, side_effect=asyncio.TimeoutError()):
            latency, error = await engine._measure_tcp("127.0.0.1", 443, 0.01)
        assert latency is None
        assert error == ERR_TCP_TIMEOUT

        with patch("asyncio.open_connection", new_callable=AsyncMock, side_effect=OSError("network unreachable")):
            latency, error = await engine._measure_tcp("127.0.0.1", 443, 0.01)
        assert latency is None
        assert error == ERR_TCP_NETWORK_ERROR
    asyncio.run(_run())

def test_probe_engine_lifecycle_pause_resume_stop():
    async def _run():
        engine = make_engine()
        assert not engine.is_paused
        assert not engine.is_stopped

        engine.pause()
        assert engine.is_paused

        engine.resume()
        assert not engine.is_paused

        engine.stop()
        assert engine.is_stopped
    asyncio.run(_run())

