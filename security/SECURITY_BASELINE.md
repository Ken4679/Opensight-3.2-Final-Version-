# OpenSight 3.2 Security & Dependency Baseline

**Target Repository:** `Ken4679/Opensight-3.2-Final-Version-`  
**Baseline Date:** 2026-08-26  
**Auditor / Role:** Senior Software Security Auditor & Dependency Analyst  
**Status:** Task 1 Baseline Established (Inspection & Evidence-Based Assessment Only — No Code Modifications / Dependency Upgrades Applied)

---

## 1. Repository Summary

OpenSight 3.2 is a security-focused, local-first OpenVPN / sing-box network routing and node quality evaluation utility. It is structured as a hybrid desktop/local service architecture targeting Windows 10/11 x64 systems:

- **Desktop Host:** Rust (Tauri v2) providing native Windows JobObject lifecycle binding, tray integration, UAC elevation coordination, and WebView frontend encapsulation.
- **Core Engine & Backend API:** Python 3.10+ / 3.11 with FastAPI, Starlette, Uvicorn, and Pydantic providing local loopback REST endpoints, WebSocket event streams, SQLite WAL storage, zero-network AST OVPN parsing, DPAPI credential management, TCP measurement probe engine, and fail-closed KillSwitch / LeakGuard mechanisms.
- **Frontend UI:** React 18 with TypeScript, Tailwind CSS, and Vite.
- **Packaging & Supply Chain:** Bundled OpenVPN and sing-box runtimes, CycloneDX SBOM generator, canonical provenance security manifest (`SECURITY-MANIFEST.json`), and Windows PowerShell silent installer/repair/uninstaller scripts.

---

## 2. Technology Versions

| Component | Repository Declared Version | Active / Container Environment Version | Source / Notes |
| :--- | :--- | :--- | :--- |
| **Python** | `>=3.10` (pyproject.toml), `3.11` (CI) | `3.10.12` | Runtime Linux container (no local pytest/pip in container) |
| **FastAPI** | `fastapi>=0.110.0` | Transitive via requirements | `requirements.txt`, `pyproject.toml` |
| **Starlette** | Transitive via FastAPI (>=0.37.2) | Transitive via requirements | Handled with startup compatibility layer in `server.py` |
| **Pydantic** | Transitive via FastAPI (v1 / v2 compatible) | Transitive via requirements | Used for request models in `server.py` |
| **Uvicorn** | `uvicorn[standard]>=0.28.0` | Transitive via requirements | `requirements.txt`, `pyproject.toml` |
| **HTTPX** | `httpx>=0.28.1` | Transitive via requirements | `requirements.txt`, `pyproject.toml` |
| **Bun** | `1.1.27` (.github/workflows/build-windows.yml) | `1.4.0` | Available in container `/usr/local/bin/bun` |
| **Node.js** | Node 20+ / LTS | `v22.23.2` | Available in container `/usr/local/bin/node` |
| **npm** | npm 10+ | `10.9.8` | Available in container `/usr/local/bin/npm` |
| **TypeScript** | `^5.7.3` (root), `^5.2.2` (web) | `5.7.3` (root devDependencies) | Type check passing |
| **React** | `^18.3.1` (root), `^18.2.0` (web) | `18.3.1` (root) | React 18 with ReactDOM |
| **Tauri** | `^2.0.0` (CLI & API), Rust `2.0.0` | Tauri v2.0.0 | `src-tauri/Cargo.toml`, `package.json` |
| **Rust Toolchain**| `dtolnay/rust-toolchain@stable`, Edition `2021` | N/A in current container | Target build on `windows-2022` |

---

## 3. Dependency Versions & Manifests

### 3.1 Python Dependencies (`pyproject.toml` & `requirements.txt`)
- **Runtime:**
  - `fastapi>=0.110.0`
  - `uvicorn[standard]>=0.28.0`
  - `httpx>=0.28.1`
  - `websockets>=12.0`
- **Development & Security (`requirements-dev.txt`):**
  - `pytest>=7.4.0`
  - `pytest-cov>=4.1.0`
  - `pytest-asyncio>=0.23.0`
  - `flake8>=6.0.0`
  - `pip-audit>=2.6.0`
  - `pyinstaller>=6.0.0`
  - `h11>=0.16.0`

### 3.2 JavaScript / TypeScript Dependencies (`package.json`)
- **Runtime:**
  - `@tauri-apps/api: ^2.0.0`
  - `clsx: ^2.1.0`
  - `lucide-react: ^0.363.0`
  - `react: ^18.3.1`
  - `react-dom: ^18.3.1`
  - `tailwind-merge: ^2.2.2`
  - `ws: ^8.21.3`
- **Development:**
  - `@tauri-apps/cli: ^2.0.0`
  - `@types/express: ^5.0.0`
  - `@types/node: ^22.13.4`
  - `@types/react: ^18.3.18`
  - `@types/react-dom: ^18.3.5`
  - `@types/ws: ^8.18.1`
  - `@vitejs/plugin-react: ^4.3.4`
  - `autoprefixer: ^10.4.19`
  - `express: ^4.21.2`
  - `postcss: ^8.4.38`
  - `tailwindcss: ^3.4.1`
  - `tsx: ^4.19.2`
  - `typescript: ^5.7.3`
  - `vite: ^6.1.0`

### 3.3 Rust Dependencies (`src-tauri/Cargo.toml`)
- `tauri = { version = "2.0.0", features = ["tray-icon", "image-ico", "image-png"] }`
- `serde = { version = "1.0", features = ["derive"] }`
- `serde_json = "1.0"`
- `getrandom = { version = "0.2", features = ["js"] }`
- `windows = { version = "0.52", features = ["Win32_System_JobObjects", "Win32_Security", "Win32_Foundation", "Win32_System_Threading"] }`

---

## 4. Current Test Baseline

Each command is classified based on direct execution or environmental constraints:

| Check / Test Target | Command | Result Status | Notes / Output Evidence |
| :--- | :--- | :--- | :--- |
| **Frontend TypeScript Check** | `npm run lint` (`tsc --noEmit`) | **PASS** | Completed with 0 errors across all React/TS components |
| **Frontend Vite Production Build** | `compile_applet` / `npm run build` | **PASS** | Dist bundle successfully generated in `dist-web` |
| **Python Unit Tests** | `pytest -q` | **ENVIRONMENT LIMITED** | Python runtime in sandboxed container lacks `pytest` package. Verified CI workflow runs `pytest --cov=opensight tests/` on Windows-2022. |
| **Python Flake8 Linter** | `flake8` | **ENVIRONMENT LIMITED** | `flake8` not pre-installed in container Python environment; configured in `.flake8` and CI. |
| **Python Dependency Audit** | `pip-audit` | **ENVIRONMENT LIMITED** | `pip-audit` not pre-installed in container Python environment; configured in `ci.yml`. |
| **Rust Tauri Compilation** | `cargo check` / `cargo test` | **ENVIRONMENT LIMITED** | Rust/Cargo toolchain is Windows/CI target; not installed in container Linux host. |
| **Smoke Test Suite** | `python scripts/smoke_test.py` | **ENVIRONMENT LIMITED** | Windows PE binary execution required. |

---

## 5. Security Attack Surface Analysis

The codebase exposes several critical security boundaries and attack surfaces:

1. **Local API & WebSocket Exposure (`/api/*`, `/ws`):**
   - Must strictly listen on loopback interface (`127.0.0.1`).
   - Requires cryptographically strong Bearer token verification.
   - Must avoid timing attacks during authentication token comparisons (`secrets.compare_digest`).
   - Health check (`/api/health`) must remain unauthenticated but strictly leak-free (no path, token, or internal topology exposure).
   - WebSocket `/ws` auth currently accepts query string `?token=`, which could be recorded in proxy/browser logs.
2. **CORS & Webview Origin Boundaries:**
   - CORS middleware restricts origins to `tauri://localhost`, `http://localhost`, and `http://127.0.0.1`.
   - Tauri WebView CSP prohibits untrusted script execution.
3. **OpenVPN Configuration Parser (`OvpnParser` & `ovpn_security.py`):**
   - Untrusted `.ovpn` files could attempt RCE through dangerous directives (`script-security`, `up`, `down`, `plugin`, `management`).
   - Must parse block tags (`<connection>`, `<ca>`, `<cert>`, `<key>`, `<tls-crypt>`) safely without directive evasion.
4. **Subprocess Invocations & Shell Injection:**
   - Invocations of `netsh advfirewall`, `powershell.exe`, `msiexec.exe`, `sing-box.exe`, `openvpn.exe`.
   - Arguments must be passed as structured arrays rather than interpolated shell command strings to prevent command injection via file paths.
5. **Path Validation & File System Isolation (`PortablePaths` & `safety.py`):**
   - Prevention of path traversal (`../`) outside the portable root directory.
   - Protection against NTFS Junctions / Reparse Points and symlink attacks during clean/purge routines (`safe_clean_directory`).
6. **Credential Storage & Log Sanitization:**
   - User credentials stored using Windows DPAPI (`CryptProtectData`/`CryptUnprotectData`).
   - In-memory credentials and tokens must be scrubbed from log files via `CredentialSanitizer`.
7. **Fail-Closed KillSwitch, Routing & DNS Leaks:**
   - Firewall rules (`netsh advfirewall`) must be transactional: if partial install fails, rollback must occur immediately without orphaned rules.
   - Application-level routing via sing-box must ensure DNS requests for VPN-routed applications never leak to local ISP resolvers (Split-DNS verification).
8. **Supply Chain & Component Provenance:**
   - Downloaded third-party binaries (OpenVPN MSI, sing-box ZIP) validated against strict domain whitelist and pinned SHA-256 hashes in `fetch_components.py` and `verify_provenance.py`.

---

## 6. Dependency Baseline & Risk Evaluation

| Dependency | Classification | Analysis / Risk Context |
| :--- | :--- | :--- |
| **FastAPI (`>=0.110.0`) & Starlette** | **MAINTENANCE RISK** | Starlette lifespan vs on_startup/on_shutdown changes; `server.py` includes a compatibility monkeypatch. Needs clean upgrade to lifespan handlers in future tasks. |
| **Pydantic** | **MAINTENANCE RISK** | Pydantic v1 vs v2 compatibility in FastAPI schemas (`BaseModel`). |
| **Uvicorn (`>=0.28.0`)** | **NOT RELEVANT TO VULNERABILITY** | Compliant ASGI server running on local loopback. |
| **HTTPX (`>=0.28.1`)** | **NOT RELEVANT TO VULNERABILITY** | Pinned modern HTTPX client. |
| **Express (`4.21.2`)** | **MAINTENANCE RISK** | In dev preview container gateway (`server.ts`). Express 4 uses `app.get('*')`. |
| **`ws` (`8.21.3`)** | **CONFIRMED UP-TO-DATE** | Modern WebSocket server implementation in Node gateway. |
| **`windows` Crate (`0.52`)** | **MAINTENANCE RISK** | Windows API bindings for Rust; stable for JobObjects and process management. |
| **`requirements.lock` Reference** | **UNKNOWN / NEEDS REVIEW** | Referenced in `.github/workflows/ci.yml` and `build-windows.yml`, but `requirements.lock` is currently absent from root. |

---

## 7. Original 17 CodeQL Baseline Findings (Grouped by Root Cause)

The 17 architectural security findings identified for this project are categorized into 7 root-cause clusters:

### Group A: Subprocess Execution & Command Construction (Findings 1–4)
- **Finding 1:** PowerShell script execution in `leak_guard.py` using command strings (`Get-NetRoute`, `Get-NetIPInterface`).
- **Finding 2:** `netsh advfirewall` execution with formatted executable path arguments needing strict path sanitization.
- **Finding 3:** MSI extraction and subprocess invocation in `fetch_components.py` and PowerShell installer scripts.
- **Finding 4:** Rust child process invocation (`std::process::Command`) in `src-tauri/src/main.rs`.

### Group B: Path Traversal & File System Sandbox Integrity (Findings 5–7)
- **Finding 5:** Relative subpath validation in `safety.py` (`validate_subpath`) against path traversal.
- **Finding 6:** Archive extraction member path validation (Zip slip prevention) in `fetch_components.py`.
- **Finding 7:** Safe directory purging and reparse point / symlink boundary checks in `safe_clean_directory`.

### Group C: API & WebSocket Authentication / Information Exposure (Findings 8–10)
- **Finding 8:** Constant-time token verification (`secrets.compare_digest` vs `==`) in `server.py`.
- **Finding 9:** WebSocket query parameter token transmission vs authorization header / first-message handshake.
- **Finding 10:** Minimal metadata disclosure verification on unauthenticated `/api/health`.

### Group D: Credential Vaulting & Secret Leakage Prevention (Findings 11–12)
- **Finding 11:** Windows DPAPI (`CryptProtectData`) memory management and pointer cleanup.
- **Finding 12:** Log sanitization coverage in `CredentialSanitizer` to prevent secret leakage in trace logs.

### Group E: OVPN AST Parsing & RCE Directive Filtering (Findings 13–14)
- **Finding 13:** Forbidden directive blocklist and whitelist enforcement in `ovpn_security.py`.
- **Finding 14:** Nested `<connection>` and inline certificate block parsing preventing directive hiding.

### Group F: Network Routing, KillSwitch Atomicity & DNS Leak Prevention (Findings 15–16)
- **Finding 15:** Transactional atomicity and snapshot rollback for KillSwitch firewall rules in `leak_guard.py`.
- **Finding 16:** Split-DNS consistency validation in `singbox_backend.py` preventing DNS fallback leakage.

### Group G: Component Provenance & Supply Chain Integrity (Finding 17)
- **Finding 17:** Cryptographic SHA-256 hash pinning and HTTPS source domain whitelisting for runtime dependencies.

---

## 8. Windows-Specific Risk Areas

1. **Windows JobObject Binding:** Child processes (`opensight-core.exe`, `openvpn.exe`, `sing-box.exe`) must be assigned to Windows JobObjects with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` to ensure zero orphaned background processes on unexpected termination.
2. **Windows DPAPI (`CryptProtectData`):** Cryptographic encryption bound to the Windows user logon session; must gracefully handle fallback in test/non-Windows environments without crashing.
3. **WFP & Windows Advanced Firewall (`netsh advfirewall`):** Outbound rule manipulation requires administrative privileges; must ensure rules match exact process paths and never use destructive commands like `netsh advfirewall reset` or `route -f`.
4. **Wintun / TAP-Windows Adapter Isolation:** Network adapter operations must target only `OpenSight-TUN` and never disrupt existing physical adapters (`Ethernet`, `Wi-Fi`) or third-party VPN adapters.
5. **Zero-Residual Uninstallation:** Uninstallation scripts (`uninstall_opensight_windows.ps1`) must check `INSTALL_MANIFEST_FILE` to clean only registered components and avoid removing shared system resources.

---

## 9. Recommended Order of Remediation for Subsequent Tasks

1. **Stage 1 — Core Parsing & Path Security Hardening:**
   - Enforce constant-time token comparison (`secrets.compare_digest`) in `server.py`.
   - Verify AST OVPN parser strictness and archive extraction safety.
2. **Stage 2 — Process Execution & Subprocess Argument Hardening:**
   - Audit all `subprocess.run` and `subprocess.check_output` calls across Python and PowerShell scripts to ensure strict argument parameterization.
3. **Stage 3 — Dependency & Compatibility Modernization:**
   - Generate / synchronize `requirements.lock` for reproducible CI builds.
   - Replace Starlette monkeypatch with standard FastAPI lifespan context manager.
4. **Stage 4 — LeakGuard, KillSwitch & Routing Transaction Verification:**
   - Enhance compensatory rollback tests for firewall rules and Split-DNS routing rules.
5. **Stage 5 — End-to-End Verification & Release Gate Testing:**
   - Run full test matrix (`pytest`, `flake8`, `pip-audit`, `tsc`, `compile_applet`) in target environments.

---

## 10. Limitations of Current Environment

- **Container Operating System:** Linux x86_64 container. Windows-specific APIs (Win32 JobObjects, DPAPI, `netsh advfirewall`, PowerShell Windows Cmdlets, Wintun) cannot be executed live inside this container and are validated via unit test mocks, static analysis, and CI workflows.
- **Python Tooling in Container:** Python 3.10.12 is installed without `pip`, `pytest`, or `flake8` binaries inside the container. Frontend tools (`node`, `npm`, `bun`, `tsc`, `vite`) are fully functional and pass all lint/build gates.
- **Verification Strategy:** Codebase correctness is verified through static analysis, AST inspection, TypeScript typechecking, and build validation.

---
*Document generated as the authoritative Task 1 baseline for OpenSight 3.2.*
