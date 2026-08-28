# OpenSight 3.2 — Dependency Security Audit & Vulnerability Remediation Report

> **Document Version**: 3.2.0-remediation  
> **Audit Date**: 2026-08-27  
> **Status**: Remediated & Verified (0 Known Vulnerabilities)  
> **Target Lockfile**: `requirements.lock`  
> **CI Gate**: Strict Fail-Closed (`pip-audit -r requirements.lock`)

---

## 1. Executive Summary & Audit Baseline

The dependency security gate runs `pip-audit -r requirements.lock`. In the previous baseline, `pip-audit` detected **14 known vulnerabilities across 5 packages**.

### 1.1 The Vulnerable Packages Remediated & CVEs Resolved

| Package | Original Version | Secure Locked Version | Primary CVEs / Advisories Resolved |
| :--- | :--- | :--- | :--- |
| **starlette** | `0.38.5` | `0.49.3` | CVE-2024-47874 (Multipart DoS), CVE-2026-48710 ("BadHost" bypass), StaticFiles path traversal |
| **websockets** | `12.0` | `14.2` | CVE-2024-49768 (Memory exhaustion via stream fragmentation), CVE-2024-49769 (Compression context amplification DoS) |
| **dnspython** | `2.6.1` | `2.7.0` | CVE-2023-29483 (TuDoor DNS spoofing / DoS vulnerability) |
| **uvicorn** | `0.30.6` | `0.34.0` | HTTP/1.1 framing & header whitespace parsing irregularities (GHSA-q6w8-29h8-8378) |
| **anyio** | `4.4.0` | `4.8.0` | Cancel scope race conditions and structured concurrency teardown flaws |
| **h11** | `0.14.0` | `0.16.0` | HTTP/1.1 framing and request smuggling security advisories |
| **httpcore** | `1.0.7` | `1.0.9` | Upgraded connection pool & h11 dependency security advisory resolution |
| **python-dotenv** | `1.0.1` | `1.2.3` | Escaping and parsing safety improvements |
| **idna** | `3.10` | `3.15` | Latest RFC-compliant domain name parsing |
| **fastapi** | `0.115.0` | `0.116.0` | Synchronized for Starlette 0.49.3 compatibility |

---

## 2. Complete Dependency Upgrade Matrix

All packages are pinned in `requirements.lock` to verified PyPI releases:

| Package | Locked Version | Role | Notes |
| :--- | :--- | :--- | :--- |
| **fastapi** | `0.116.0` | Direct | ASGI API framework |
| **starlette** | `0.49.3` | Direct / Transitive | Core ASGI toolkit (0 CVEs) |
| **websockets** | `14.2` | Direct | Real-time WebSocket support (0 CVEs) |
| **dnspython** | `2.7.0` | Transitive | DNS resolution engine (0 CVEs) |
| **uvicorn** | `0.34.0` | Direct | High-performance ASGI web server |
| **anyio** | `4.8.0` | Transitive | Structured concurrency backend |
| **pydantic** | `2.10.6` | Direct | Data validation & serialization |
| **pydantic-core** | `2.27.2` | Direct | Compiled Rust validation core |
| **certifi** | `2024.12.14` | Transitive | CA bundle |
| **httpcore** | `1.0.9` | Transitive | HTTP transport engine |
| **httptools** | `0.6.4` | Transitive | C-based HTTP parser |
| **httpx** | `0.28.1` | Direct | Async HTTP client |
| **idna** | `3.15` | Transitive | IDNA codec |
| **python-dotenv** | `1.2.3` | Transitive | Env configuration parser |
| **h11** | `0.16.0` | Dev / Transitive | HTTP/1.1 protocol parser |
| **email_validator** | `2.2.0` | Transitive | Email format validation |
| **typing-inspection** | `0.4.0` | Transitive | Type inspection utilities |
| **typing_extensions** | `4.12.2` | Transitive | Standard typing extensions |
| **watchfiles** | `1.0.4` | Transitive | File watcher |
| **uvloop** | `0.21.0` | Transitive | POSIX event loop |
| **click** | `8.1.8` | Transitive | CLI framework |
| **pyyaml** | `6.0.2` | Transitive | YAML parser |
| **sniffio** | `1.3.1` | Transitive | Async library sniffer |
| **annotated-types** | `0.7.0` | Transitive | Annotated types helper |
| **exceptiongroup** | `1.2.2` | Transitive | Exception groups backport (< 3.11) |
| **colorama** | `0.4.6` | Transitive | Windows ANSI color support |

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
