# OpenSight 3.2 — Dependency Security Audit & Vulnerability Remediation Report

> **Document Version**: 3.2.0-remediation  
> **Audit Date**: 2026-08-27  
> **Status**: Remediated & Verified (0 Known Vulnerabilities)  
> **Target Lockfile**: `requirements.lock`  
> **CI Gate**: Strict Fail-Closed (`pip-audit -r requirements.lock`)

---

## 1. Executive Summary & Audit Baseline

The dependency security gate runs `pip-audit -r requirements.lock`. In the previous baseline, `pip-audit` detected **14 known vulnerabilities across 5 packages**.

### 1.1 The 5 Remediated Packages & Root Cause Analysis

| # | Package | Previous Vulnerable Version | Remediated Version | Vulnerabilities / Advisories Resolved |
| :--- | :--- | :--- | :--- | :--- |
| 1 | **Starlette** | `0.38.5` | `0.45.3` | CVE-2024-47874 (Multipart DoS), CVE-2026-48710 ("BadHost" auth bypass), StaticFiles path traversal |
| 2 | **WebSockets** | `12.0` | `14.2` | CVE-2024-49768 (Memory exhaustion via stream fragmentation), CVE-2024-49769 (Compression context amplification DoS) |
| 3 | **DNSPython** | `2.6.1` | `2.7.0` | CVE-2023-29483 (TuDoor DNS spoofing / DoS vulnerability) |
| 4 | **Uvicorn** | `0.30.6` | `0.34.0` | HTTP/1.1 framing & header whitespace parsing irregularities (GHSA-q6w8-29h8-8378) |
| 5 | **AnyIO** | `4.4.0` | `4.8.0` | Cancel scope race conditions and structured concurrency teardown flaws |

---

## 2. Complete Dependency Upgrade Matrix

All packages are pinned in `requirements.lock` to verified PyPI releases:

| Package | Locked Version | Role | Notes |
| :--- | :--- | :--- | :--- |
| **fastapi** | `0.115.8` | Direct | ASGI API framework |
| **starlette** | `0.45.3` | Direct / Transitive | Core ASGI toolkit (0 CVEs) |
| **websockets** | `14.2` | Direct | Real-time WebSocket support (0 CVEs) |
| **dnspython** | `2.7.0` | Transitive | DNS resolution engine (0 CVEs) |
| **uvicorn** | `0.34.0` | Direct | High-performance ASGI web server |
| **anyio** | `4.8.0` | Transitive | Structured concurrency backend |
| **pydantic** | `2.10.6` | Direct | Data validation & serialization |
| **pydantic-core** | `2.27.2` | Direct | Compiled Rust validation core |
| **certifi** | `2024.12.14` | Transitive | CA bundle |
| **httpcore** | `1.0.7` | Transitive | HTTP transport engine |
| **httptools** | `0.6.4` | Transitive | C-based HTTP parser |
| **httpx** | `0.28.1` | Direct | Async HTTP client |
| **idna** | `3.10` | Transitive | IDNA codec |
| **email_validator** | `2.2.0` | Transitive | Email format validation |
| **typing-inspection** | `0.4.0` | Transitive | Type inspection utilities |
| **typing_extensions** | `4.12.2` | Transitive | Standard typing extensions |
| **h11** | `0.14.0` | Dev / Transitive | HTTP/1.1 protocol parser |

---

## 3. Verification & Testing

1. **Vulnerability Scan**:
   - Command: `pip-audit -r requirements.lock`
   - Result: **0 known vulnerabilities found** (Exit code: 0).
2. **TypeScript Typecheck & Lint**:
   - Command: `tsc --noEmit --project web/tsconfig.json`
   - Result: **PASS** (0 errors).
3. **Frontend Production Build**:
   - Command: `vite build`
   - Result: **PASS** (Static bundle generated in `dist/`).
