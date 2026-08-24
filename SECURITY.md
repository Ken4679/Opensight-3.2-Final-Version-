# OpenSight Security Policy & Architecture Model

## 1. Supported Versions

| Version | Supported | Security Patch Policy |
| :--- | :--- | :--- |
| **3.2.x** | :white_check_mark: Yes | Active security and stability updates |
| < 3.2.0 | :x: No | End of Life (Upgrade recommended) |

---

## 2. Threat Model & Security Boundaries

OpenSight is a **desktop-native, local-first network routing and VPN management system** running on Windows (Windows 10 / Windows 11 x64).

### 2.1 Security Assumptions & Invariants
1. **Local-Only API Binding**: The Python core (`opensight-core`) binds strictly to loopback (`127.0.0.1`). It never binds to external interfaces (`0.0.0.0`) or listens on public sockets.
2. **Mandatory Production Authentication**: Local REST and WebSocket endpoints require a cryptographically secure 256-bit Bearer token (`Authorization: Bearer <token>`). Unauthenticated requests are rejected with `401 Unauthorized`.
3. **CORS & Origin Whitelisting**: Cross-Origin Resource Sharing is strictly constrained to `tauri://localhost`, `http://localhost`, `http://127.0.0.1`, and explicit header whitelists (`Authorization`, `Content-Type`, `X-Requested-With`, `Accept`).
4. **WebView Content Security Policy (CSP)**: The Tauri WebView enforces strict script and resource execution boundaries (`object-src 'none'`, `frame-ancestors 'none'`, restricted `connect-src`).
5. **No Telemetry / No Phoning Home**: OpenSight does not operate remote servers, tracking pixels, or third-party telemetry collectors.
6. **/api/health Endpoint**: `/api/health` is intentionally unauthenticated and returns only minimal application status metadata (`status`, `app`, `version`) without exposing tokens, paths, credentials, or internal system configurations.

---

## 3. Core Protection Mechanisms

### 3.1 OpenVPN Configuration Security (AST Whitelist)
When importing `.ovpn` configuration profiles:
- Parsing uses a strict tokenized AST parser.
- Dangerous script execution directives (`up`, `down`, `route-up`, `route-pre-down`, `client-connect`, `client-disconnect`, `script-security`, `plugin`, `management-query-passwords`) are stripped or rejected.
- Inline script injections, UNC paths (`\\server\share`), and directory traversal payloads (`../`) are blocked.

### 3.2 Windows DPAPI Credential Vault
- User credentials are stored either in ephemeral session memory (default) or encrypted via Windows DPAPI (`CryptProtectData` with user-level key protection).
- Master keys are managed by Windows OS and bound to the logged-in user account.
- Plaintext credentials and auth tokens are registered with `CredentialSanitizer` to prevent accidental emission into application log files.

### 3.3 Fail-Closed KillSwitch & LeakGuard
- Application-level KillSwitch leverages Windows Advanced Firewall (WFP / `netsh advfirewall`) blocking rules.
- On sudden VPN process termination or crash, traffic for protected applications is blocked at the firewall layer, avoiding cleartext network leakage.
- Disconnection routines execute idempotent state rollbacks.

### 3.4 Windows JobObject Process Lifecycle
- Background sub-processes (`opensight-core.exe`, `openvpn.exe`, `sing-box.exe`) are bound to Windows `JobObject` with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
- When the parent UI exits or crashes, all child network routing and proxy processes are terminated by the Windows kernel.

### 3.5 Release Integrity & Code Signing Policy
- **Personal Release Integrity**: As a personal/community open-source project, OpenSight does not purchase commercial Authenticode EV/OV certificates. Code signing is **NOT REQUIRED FOR PERSONAL RELEASE**.
- **Provenance & Verification**: Every release includes:
  - Cryptographic SHA-256 checksums (`SHA256SUMS.txt`)
  - Standardized CycloneDX SBOM (`SBOM.cdx.json`)
  - Canonical provenance security manifest (`SECURITY-MANIFEST.json`)
  - Strict pinned hash verification of bundled third-party runtimes (OpenVPN, sing-box).
- **Windows SmartScreen**: First-time execution may trigger a standard Windows SmartScreen prompt on unsigned binaries; users can verify binary integrity against the official GitHub Release SHA256 hash.

---

## 4. Reporting a Vulnerability

If you discover a security vulnerability or bypass in OpenSight:
1. **Do not create public GitHub issues** for zero-day vulnerabilities.
2. Please submit a private security advisory through **GitHub Security Advisories** or contact the maintainers.
3. Provide detailed reproduction steps, proof of concept (PoC), and affected environment versions.
4. We aim to acknowledge reports within 48 hours and provide security patches in regular release candidates.
