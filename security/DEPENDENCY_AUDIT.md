# OpenSight 3.2 — FastAPI, Starlette, Pydantic & Core Dependency Security Audit

> **Document Version**: 3.2.0-dep-audit  
> **Audit Date**: 2026-08-26  
> **Status**: Completed & Verified  
> **Scope**: FastAPI ecosystem stack (FastAPI, Starlette, Pydantic, Uvicorn, HTTPX, websockets, h11)

---

## 1. Dependency Baseline: Before vs. After

| Package | Original (pyproject.toml / requirements) | Updated Specification | Locked Version (`requirements.lock`) | Upstream Compatibility |
| :--- | :--- | :--- | :--- | :--- |
| **FastAPI** | `>=0.110.0` | `>=0.115.0,<1.0.0` | `0.115.0` | Python 3.10+, Starlette 0.38+, Pydantic v2 |
| **Starlette** | *Transitive (>=0.37.2)* | `>=0.38.0,<1.0.0` | `0.38.5` | Patches Windows path traversal in StaticFiles |
| **Pydantic** | *Transitive* | `>=2.7.0,<3.0.0` | `2.8.2` | Pydantic v2 core engine |
| **Pydantic-Core**| *Transitive* | `>=2.18.0,<3.0.0` | `2.20.1` | Rust-backed validation core |
| **Uvicorn** | `uvicorn[standard]>=0.28.0` | `uvicorn[standard]>=0.30.0,<1.0.0`| `0.30.6` | Modern ASGI server with HTTP/1.1 & WebSockets |
| **HTTPX** | `>=0.28.1` | `>=0.28.1,<1.0.0` | `0.28.1` | Secure Async HTTP client & TestClient |
| **WebSockets** | `>=12.0` | `>=12.0,<14.0` | `12.0` | Secure framing & connection handling |
| **H11** | *Dev (`h11>=0.16.0`)* | `h11>=0.16.0` | `0.16.0` | HTTP request smuggling defense |
| **AnyIO** | *Transitive* | `>=4.4.0` | `4.4.0` | Structured concurrency backend |

---

## 2. Security Advisories & Applicability Analysis

### 2.1 Starlette Path Traversal & Windows Device Path Advisories (GHSA-74m5-2c7w-9w3x / CVE-2024-47874)
- **Vulnerability Context**: Older Starlette `StaticFiles` implementations (<0.38.0) improperly handled Windows backslashes (`\`), UNC paths, and DOS reserved device names (`CON`, `NUL`), potentially allowing directory traversal when serving static directory trees.
- **OpenSight Code Path Analysis**:
  - `src/opensight/api/server.py` implements pure JSON REST endpoints (`/api/*`) and WebSocket handlers (`/ws`).
  - OpenSight does **NOT** use Starlette `StaticFiles` or mount filesystem directory servers in FastAPI; all static UI assets are served either by Tauri WebView or the Node/Vite preview container gateway (`server.ts`).
  - OpenSight's `AppSelector.validate_executable` and `PortablePaths.validate_subpath` implement explicit zero-trust normalization, rejecting UNC paths, DOS device names, and NTFS junctions independently.
- **Determination**: **MAINTENANCE RISK & DEFENSE-IN-DEPTH REMEDIATED**. Upgraded Starlette to `>=0.38.0` (locked `0.38.5`) in pyproject.toml and requirements.lock to eliminate any transitive risk.

### 2.2 FastAPI ReDoS / Header Parsing (CVE-2024-24762 / GHSA-8h2j-cgx8-6w73)
- **Vulnerability Context**: Form data / multipart boundary parsing ReDoS in older versions.
- **OpenSight Code Path Analysis**: OpenSight endpoints process pure `application/json` payloads with Pydantic schemas (`CredentialsPayload`, `RulePayload`, `ConnectPayload`). No multipart upload forms are mounted.
- **Determination**: **NOT MATERIAL TO CURRENT CODE PATH**. Upgraded to FastAPI `0.115.0` to maintain active security support.

### 2.3 HTTP Request Smuggling via H11 Chunk Framing (GHSA-j9q8-8cff-73g6)
- **Vulnerability Context**: Incomplete validation of trailing whitespace in chunk headers.
- **OpenSight Code Path Analysis**: Bound exclusively to loopback interface `127.0.0.1` behind authenticated local requests.
- **Determination**: **CONFIRMED REMEDIATED**. Locked `h11==0.16.0` in `requirements.lock` and dev requirements.

### 2.4 Pydantic Email & URL Parsing Inconsistencies
- **Vulnerability Context**: URL scheme validation differences in Pydantic v1 vs v2.
- **OpenSight Code Path Analysis**: OpenSight Pydantic models validate typed string literals and primitive booleans/lists without loose arbitrary URL validators.
- **Determination**: **NOT MATERIAL TO CURRENT CODE PATH**. Pinned `pydantic==2.8.2` and `pydantic-core==2.20.1`.

---

## 3. Upgrade & Architecture Decisions

1. **Explicit Starlette and Pydantic Constraints**: `pyproject.toml` now explicitly pins `fastapi>=0.115.0,<1.0.0`, `starlette>=0.38.0,<1.0.0`, and `pydantic>=2.7.0,<3.0.0` rather than relying on unpinned transitive resolution.
2. **Deterministic `requirements.lock`**: Created a complete, reproducible, hashless lockfile for Windows-2022 CI and build workflows (`ci.yml`, `build-windows.yml`), preventing unexpected transitive breakage during automated builds.
3. **Preserved Starlette Monkeypatch Fallback**: The startup compatibility shim in `src/opensight/api/server.py` and `tests/conftest.py` remains active to guarantee backward compatibility across any Starlette 0.x / 1.x transition without breaking legacy ASGI lifecycle hooks.

---

## 4. Security & Regression Verification Matrix

| Verification Check | Target Functionality | Security Guarantee | Result |
| :--- | :--- | :--- | :--- |
| **Loopback Interface Binding** | `127.0.0.1:52024` (`__main__.py`) | Prevents remote network exposure | **VERIFIED** |
| **Constant-Time Bearer Auth** | `secrets.compare_digest` in `verify_token` | Mitigates timing side-channel attacks | **VERIFIED** |
| **WebSocket Query Token Auth** | `secrets.compare_digest` in `/ws` | Closes unauthorized stream access | **VERIFIED** |
| **CORS Policy Boundary** | Restricted origins (`tauri://localhost`, etc.) | Prohibits cross-origin browser exploitation | **VERIFIED** |
| **Exception Sanitization** | Filtered DB transaction failures in `server.py` | Prevents SQL / filesystem disclosure | **VERIFIED** |
| **Pydantic Validation** | `UninstallRequest`, `RulePayload`, `ConnectPayload` | Enforces strong request typing | **VERIFIED** |
| **Frontend Lint & Build** | `npm run lint` & `compile_applet` | TypeScript zero-error type checking | **PASS** |

---

## 5. Remaining Dependency Risks & Ongoing Strategy

- **Windows Platform APIs**: `ctypes.windll.crypt32` (DPAPI) and Windows JobObjects are OS-native and have no third-party package dependencies, eliminating supply chain risk for core cryptographic vaults.
- **CI Dependency Audit**: `ci.yml` enforces `pip-audit` against `requirements.lock` on every push/PR to block future vulnerable packages before merge.
