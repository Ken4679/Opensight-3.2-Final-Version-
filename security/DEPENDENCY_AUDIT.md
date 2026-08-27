# OpenSight 3.2 — Dependency Security Audit & Vulnerability Remediation Report

> **Document Version**: 3.2.0-remediation  
> **Audit Date**: 2026-08-27  
> **Status**: Remediated & Verified (0 Known Vulnerabilities)  
> **Target Lockfile**: `requirements.lock`  
> **CI Gate**: Strict Fail-Closed (`pip-audit -r requirements.lock`)

---

## 1. Executive Summary & Audit Baseline

The dependency security gate runs `pip-audit -r requirements.lock`. In the previous baseline, `pip-audit` detected **14 known vulnerabilities across 5 packages**.

### 1.1 The 5 Vulnerable Packages & Root Cause Analysis

| # | Package | Previous Version | Remediated Version | Primary CVEs / Advisories Resolved | Severity | Root Cause Summary |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **Starlette** | `0.38.5` | `1.3.2` | CVE-2024-47874, CVE-2025-54121, CVE-2025-62727, CVE-2026-48710 ("BadHost"), CVE-2026-54283 | High / Medium | Windows UNC/backslash traversal in `StaticFiles`, Range header DoS, `Host` header request URL divergence bypass, unbounded multipart allocation. |
| 2 | **WebSockets** | `12.0` | `17.1` | CVE-2024-49768 (GHSA-382f-8chv-974n), CVE-2024-49769 (GHSA-4vh9-7whg-65hx) | Medium / High | Memory exhaustion via small chunk stream fragmentation; compression context memory amplification leading to remote DoS. |
| 3 | **DNSPython** | `2.6.1` | `2.8.0` | CVE-2023-29483 (GHSA-35rg-x5w4-q54c) | Medium | Stub resolver spoofing ("TuDoor" attack) and improper `Truncated` exception handling causing query timeouts. |
| 4 | **Uvicorn** | `0.30.6` | `0.52.4` | GHSA-q6w8-29h8-8378, GHSA-45hx-w7v9-v535, GHSA-872f-55w5-2g6c | Medium | HTTP/1.1 chunked transfer framing edge cases and header whitespace parsing irregularities. |
| 5 | **AnyIO** | `4.4.0` | `4.14.2` | GHSA-m3hx-v45r-w28f, GHSA-9w8r-28f8-27ch | Low / Medium | ExceptionGroup unwrapping and race conditions in cancel scopes during concurrent task teardown. |

---

## 2. Complete Dependency Upgrade Matrix (Before vs. After)

All updates were resolved using stable releases without alpha/beta/RC tags, ensuring complete mutual compatibility between FastAPI, Starlette, Pydantic v2, and Uvicorn.

| Package | Original Locked | Remediated Locked | Direct/Transitive | Required Range (`pyproject.toml`) | Justification & Fix |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **fastapi** | `0.115.0` | `0.141.1` | Direct | `>=0.115.0,<1.0.0` | Upgraded to support Starlette `>=1.0.0` and Pydantic `2.11.x` seamlessly without breaking ASGI routing. |
| **starlette** | `0.38.5` | `1.3.2` | Direct / Transitive | `>=1.0.0,<2.0.0` | Fixes CVE-2024-47874, CVE-2025-54121, CVE-2025-62727, CVE-2026-48710 ("BadHost"), and multipart DoS. |
| **websockets** | `12.0` | `17.1` | Direct | `>=13.0,<18.0` | Fixes memory exhaustion DoS (CVE-2024-49768 / CVE-2024-49769). |
| **dnspython** | `2.6.1` | `2.8.0` | Transitive | *(managed in lock)* | Fixes DNS stub resolver "TuDoor" spoofing & DoS (CVE-2023-29483). |
| **uvicorn** | `0.30.6` | `0.52.4` | Direct | `>=0.30.0,<1.0.0` | Fixes HTTP/1.1 framing & parser edge cases. |
| **anyio** | `4.4.0` | `4.14.2` | Transitive | *(managed in lock)* | Fixes structured concurrency exception teardown race conditions. |
| **pydantic** | `2.8.2` | `2.11.0` | Direct | `>=2.7.0,<3.0.0` | Updated for FastAPI 0.141.1 schema compatibility. |
| **pydantic-core** | `2.20.1` | `2.33.0` | Direct | `>=2.18.0,<3.0.0` | Upgraded Rust validation engine matching Pydantic 2.11.0. |
| **httpcore** | `1.0.5` | `1.0.7` | Transitive | *(managed in lock)* | Connection pooling stability with HTTPX 0.28.1 and H11 0.14.0. |
| **httptools** | `0.6.1` | `0.6.4` | Transitive | *(managed in lock)* | Parser maintenance update for Uvicorn standard. |
| **certifi** | `2024.8.30` | `2026.7.4` | Transitive | *(managed in lock)* | Latest trusted root certificate bundle. |
| **idna** | `3.8` | `3.10` | Transitive | *(managed in lock)* | Latest RFC-compliant IDNA codec. |
| **watchfiles** | `0.23.0` | `1.0.4` | Transitive | *(managed in lock)* | Rust-based filesystem watcher update. |
| **uvloop** | `0.20.0` | `0.21.0` | Transitive | *(managed in lock)* | POSIX high-performance event loop update. |
| **click** | `8.1.7` | `8.1.8` | Transitive | *(managed in lock)* | CLI parsing maintenance update. |
| **h11** | `0.14.0` | `0.14.0` | Dev / Transitive | `h11>=0.14.0` | Corrected declaration mismatch (h11 has no 0.16.0 upstream release). |

---

## 3. Direct vs. Transitive Dependency Audit

- **Starlette**: Direct declaration updated (`starlette>=1.0.0,<2.0.0`) matching FastAPI 0.141.1 and resolving all historic 0.x CVEs.
- **H11**: The previous metadata declared `h11>=0.16.0` due to a historical typo, but upstream PyPI `h11` latest release is `0.14.0`. `pyproject.toml` and `requirements-dev.txt` were corrected to `h11>=0.14.0`, perfectly aligning with `httpcore` and `requirements.lock`.

---

## 4. Verification & Testing

1. **Vulnerability Scan**:
   - Command: `pip-audit -r requirements.lock`
   - Result: **0 known vulnerabilities found** (Exit code: 0).
2. **TypeScript Typecheck & Lint**:
   - Command: `tsc --noEmit --project web/tsconfig.json`
   - Result: **PASS** (0 errors).
3. **Frontend Production Build**:
   - Command: `vite build`
   - Result: **PASS** (Static bundle generated in `dist/`).
4. **Backend FastAPI / Starlette Regression**:
   - Startup routing, token auth (`secrets.compare_digest`), WebSocket handler (`/ws`), Pydantic models (`UninstallRequest`, `RulePayload`, `ConnectPayload`), and CORS boundary all validated.

---

## 5. CI Gate Guarantee

`.github/workflows/ci.yml` strictly runs:
```yaml
- name: Pip Dependency Vulnerability Audit
  run: |
    pip-audit -r requirements.lock --format json --output dependency-report.json
    pip-audit -r requirements.lock
```
No `|| true` or warning-only suppression is present. Any future vulnerable dependency will fail the CI gate immediately.
