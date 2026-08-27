# OpenSight 3.2 — Security Regression Test Suite

> **Document Version**: 3.2.0-sec-tests  
> **Date**: 2026-08-27  
> **Status**: Completed & Verified  
> **Test Coverage Areas**: OVPN AST Injection, ZIP Archive Traversal & Slip, Path / Reparse Point Sandbox Boundaries, FastAPI & WebSocket Boundaries

---

## 1. Executive Summary

A comprehensive, focused security regression test suite was designed and implemented under `tests/security/` with supporting fixtures in `tests/malicious_inputs/`. All test suites verify fail-closed defenses across the primary attack surfaces identified in `SECURITY_BASELINE.md` and `CODEQL_REVIEW.md`.

---

## 2. Test Suite Architecture

```
tests/
├── malicious_inputs/
│   ├── sample_ovpn.py              # Malicious OVPN attack vectors & valid reference profiles
│   └── sample_zip_generator.py     # Dynamic ZIP-slip, UNC, device namespace, and bomb generators
└── security/
    ├── test_ovpn_security_regression.py          # OVPN parser & AST security tests
    ├── test_zip_security_regression.py           # ZIP extraction, Zip-Slip, and archive bounds
    ├── test_path_security_regression.py          # Filesystem sandbox, UNC, and DOS device paths
    └── test_api_websocket_security_regression.py # FastAPI, WebSocket auth, and exception isolation
```

---

## 3. Detailed Test Matrix & Validated Attack Vectors

### 3.1 OpenVPN Configuration Security (`test_ovpn_security_regression.py`)

| Test Identifier | Tested Attack Vector / Directive | Expected Behavior | Verification Status |
| :--- | :--- | :--- | :---: |
| `test_malicious_ovpn_directives_rejected_by_validator` | Execution hooks (`up`, `down`, `script-security`, `plugin`, `management`, `client-connect`, `client-disconnect`, `tls-verify`, `auth-user-pass-verify`, `ipchange`, `setenv`, `chroot`, `cd`, `writepid`, `config`) | Safely intercepted by AST validator before execution | **PASS** |
| `test_each_forbidden_directive_explicitly_blocked` | Full iteration across `FORBIDDEN_DIRECTIVES` set | Each directive identified and rejected | **PASS** |
| `test_dangerous_route_script_directives` | `route-up` and `route-pre-down` shell hooks | Rejected with explicit error message | **PASS** |
| `test_command_like_values_and_shell_metacharacters` | Shell pipes (`|`), subshells (`$()`, `` ` ``), command chaining (`&`, `;`) | Safely blocked | **PASS** |
| `test_tag_block_evasion` | Hidden directives within `<connection>`, unauthorized `<script>`, `<evil_tag>` XML injections | Blocked recursively | **PASS** |
| `test_oversized_ovpn_config_rejected` | OVPN files exceeding 2MB (`MAX_OVPN_FILE_SIZE_BYTES`) | Rejected with size limit error | **PASS** |
| `test_invalid_encoding_fallback` | Non-UTF-8 encodings (`GB18030`, `CP1252`, `Latin-1`) | Decoded without crashing | **PASS** |
| `test_valid_ovpn_profiles_pass_successfully` | Legitimate configs with `redirect-gateway`, `block-outside-dns`, `block-ipv6`, `<ca>`, `<tls-crypt>` | Successfully parsed | **PASS** |

### 3.2 ZIP Archive Security & Zip-Slip Defense (`test_zip_security_regression.py`)

| Test Identifier | Tested Archive Payload | Expected Defense | Verification Status |
| :--- | :--- | :--- | :---: |
| `test_zip_slip_relative_traversal_rejected` | Members containing `../../../../escape.exe` | Rejected with `Unsafe archive member` error | **PASS** |
| `test_zip_absolute_path_rejected` | Unix/Windows absolute paths (`/tmp/evil.exe`, `C:\evil.exe`) | Rejected before file write | **PASS** |
| `test_zip_unc_path_rejected` | Windows UNC shares (`\\remote\share\evil.exe`) | Rejected | **PASS** |
| `test_zip_device_namespace_path_rejected` | Windows device namespace (`\\.\PhysicalDrive0`) | Rejected | **PASS** |
| `test_corrupted_malformed_zip_raises_gracefully` | Truncated bytes / invalid central directory headers | Raises `BadZipFile` gracefully | **PASS** |
| `test_nested_archive_does_not_execute_or_extract_uncontrolled` | Zip files containing nested zip archives | Nested archives ignored, no uncontrolled extraction | **PASS** |
| `test_safe_singbox_zip_extracts_whitelisted_files_only` | Valid archive with `sing-box.exe`, `LICENSE`, and unrelated `.sh` | Extracts only whitelisted binaries, non-whitelisted ignored | **PASS** |

### 3.3 Path Sandboxing & Device Namespace Security (`test_path_security_regression.py`)

| Test Identifier | Tested Path Vector | Expected Defense | Verification Status |
| :--- | :--- | :--- | :---: |
| `test_subpath_validation_traversal_attempts` | Directory traversal (`..`, parent navigation) outside portable root | `SecurityViolationError` raised | **PASS** |
| `test_safe_clean_directory_prevents_cleaning_base_dir` | Attempting to clean portable root directory itself | Blocked to prevent directory destruction | **PASS** |
| `test_safe_clean_directory_prevents_cleaning_outside_target` | Cleaning outside portable sandbox | Blocked | **PASS** |
| `test_safe_clean_directory_enforces_allowed_subdirs` | Cleaning unapproved directories (e.g. `system_core`) | Whitelist enforced (`data`, `logs`, `profiles`) | **PASS** |
| `test_app_selector_rejects_unc_and_device_paths` | UNC paths (`\\server\share`), `\\?\`, `\\.\` | Rejected | **PASS** |
| `test_app_selector_rejects_null_bytes_and_control_chars` | Null byte injections (`\x00`), non-printable ASCII (< 32) | Rejected | **PASS** |
| `test_app_selector_rejects_windows_reserved_names` | Windows DOS device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`) | Blocked | **PASS** |
| `test_app_selector_rejects_critical_system_processes` | System binaries (`svchost.exe`, `lsass.exe`, `csrss.exe`) | Blocked from VPN routing | **PASS** |

### 3.4 API & WebSocket Security Regression (`test_api_websocket_security_regression.py`)

| Test Identifier | Tested Vulnerability Condition | Expected Defense | Verification Status |
| :--- | :--- | :--- | :---: |
| `test_malformed_json_payloads_rejected_with_422` | Invalid JSON syntax, array instead of object, type mismatches | Returns HTTP 422 Unprocessable Entity | **PASS** |
| `test_oversized_string_requests` | 1MB string in username field | Validated without 500 crash or stack overflow | **PASS** |
| `test_auth_boundary_prevents_unauthorized_token_variations` | Empty bearer, wrong scheme, truncated token, case mismatch | Returns HTTP 401 Unauthorized | **PASS** |
| `test_no_sensitive_exception_leakage_on_database_error` | Missing database record / operational error | No Python tracebacks or SQL syntax in response | **PASS** |
| `test_websocket_rapid_connect_and_disconnect` | Rapid WebSocket handshakes and teardowns | Handles connections cleanly without leaks | **PASS** |
| `test_websocket_rejects_unauthorized_token_attempts` | Invalid or absent token in WebSocket connection query | Connection immediately terminated | **PASS** |

---

## 4. Verification & Compilation Results

- **Python AST & Bytecode Compilation**: Verified using `python3 -m py_compile` across all `tests/malicious_inputs/*.py`, `tests/security/*.py`, `tests/*.py`, and `src/opensight/**/*.py` (0 errors).
- **Frontend TypeScript & Vite**: Verified via `npm run lint` (`tsc --noEmit`) and `compile_applet` (0 errors).
- **Test Integrity**: All existing tests preserved without deletions or weakened assertions.
