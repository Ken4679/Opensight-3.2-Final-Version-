# OpenSight 3.2 — CI/CD Pipeline Architecture & Security Design

> **Document Version**: 3.2.0-ci-design  
> **Date**: 2026-08-27  
> **Status**: Approved & Implemented  
> **Target Platform**: GitHub Actions (Free-Tier Optimized, Standard Hosted Runners)

---

## 1. Overview & Tiered Workflow Strategy

OpenSight 3.2 adopts a **tiered CI/CD architecture** designed for high security, fast developer feedback, zero supply-chain leakage, and strict cost/resource governance within GitHub's free-tier runtime budgets (2,000 minutes/month).

```
┌────────────────────────────────────────────────────────────────────────┐
│                              Tier 1: CI                                │
│         Trigger: Every Push / PR (main, master)  [ubuntu-latest]       │
│  Flake8 + Pip-Audit + TypeScript Check + Pytest Suite + Vite Build     │
│             Fast feedback (< 2 mins) • 1x Runner Multiplier            │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
         ┌─────────────────────────┴─────────────────────────┐
         ▼                                                   ▼
┌─────────────────────────────────┐       ┌─────────────────────────────────┐
│     Tier 2: Windows E2E         │       │     Tier 3: Deep Security       │
│  Trigger: Dispatch / VPN PRs    │       │  Trigger: Dispatch (On Demand)  │
│        [windows-2022]           │       │         [ubuntu-latest]         │
│  Security Corpus + Win Routes   │       │  Failure Injection + Fuzz Smoke │
│  PS1 AST Check + LeakGuard Test │       │  Probe Resilience + AST Fuzzing │
└─────────────────────────────────┘       └─────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      Release Gate: Tagged Builds                       │
│              Trigger: push tags v*.*.*  [windows-2022]                 │
│   Full Suite + Binary Compilation + GPG Signature Verify + SHA256      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Workflow Specifications

### Tier 1: Fast Quality & Security Gate (`.github/workflows/ci.yml`)

- **Purpose**: Rapid gating on every code change to prevent syntax errors, broken type definitions, vulnerable Python dependencies, or regression test failures.
- **Trigger**:
  - `push: branches: [main, master]`
  - `pull_request: branches: [main, master]`
- **Concurrency**: `ci-${{ github.ref }}` with `cancel-in-progress: true` (cancels redundant runs when rapid commits are pushed).
- **Runner**: `ubuntu-latest` (1x cost multiplier, fastest spin-up).
- **Timeout**: 10 minutes.
- **Executed Tests & Steps**:
  1. `actions/checkout@v4` with `persist-credentials: false`
  2. Setup Python 3.11 with pip caching enabled
  3. Setup Bun 1.1.27 (`oven-sh/setup-bun@v2`)
  4. Locked dependency installation: `pip install -r requirements-dev.txt -r requirements.lock -e .` & `bun install --frozen-lockfile`
  5. Python linting: `flake8 src tests --config=.flake8`
  6. Dependency vulnerability scanning: `pip-audit -r requirements.lock`
  7. Frontend static typing check: `bun run lint` (`tsc --noEmit`)
  8. Python unit & regression tests with coverage: `pytest --cov=opensight --junitxml=test-report.xml`
  9. Frontend build verification: `bun run build`
- **Artifacts**: `test-report.xml`, `coverage.xml`, `dependency-report.json` (7-day retention).

---

### Tier 2: Windows E2E & Platform Validation (`.github/workflows/windows-e2e.yml`)

- **Purpose**: Deep integration testing of Windows-specific networking, route interception, sandbox uninstallation, and the full security attack corpus.
- **Trigger**:
  - `workflow_dispatch` (Manual trigger)
  - `pull_request` filtered strictly to changes in `src/opensight/vpn/**`, `scripts/**`, or `.github/workflows/windows-e2e.yml`.
- **Runner**: `windows-2022` (Standard hosted runner).
- **Timeout**: 15 minutes.
- **Executed Tests & Steps**:
  1. Full security regression corpus (`tests/security/test_ovpn_security_regression.py`, `test_zip_security_regression.py`, `test_path_security_regression.py`, `test_api_websocket_security_regression.py`)
  2. Windows routing and process isolation tests (`tests/test_routing_features.py`)
  3. Zero-residual uninstallation tests (`tests/test_uninstallation_zero_residual.py`)
  4. KillSwitch and LeakGuard protection tests (`tests/test_killswitch_and_leakguard.py`)
  5. Native PowerShell script AST and syntax verification without executing external commands (`System.Management.Automation.Language.Parser`)
- **Artifacts**: `security-corpus-report.xml`, `windows-e2e-report.xml` (7-day retention).

---

### Tier 3: Deep Security & Failure Injection (`.github/workflows/deep-security.yml`)

- **Purpose**: Stress testing under failure scenarios (corrupted network states, malformed OVPN configs, Zip-Slip files, oversized payloads, probe timeout faults).
- **Trigger**:
  - `workflow_dispatch` with customizable input parameter (`fuzz_cycles`, default `50`).
- **Runner**: `ubuntu-latest` (cost-effective standard runner).
- **Timeout**: 15 minutes.
- **Executed Tests & Steps**:
  1. Failure injection & probe engine error handling tests (`tests/test_failure_modes.py`, `tests/test_probe_engine_errors.py`)
  2. Malicious OVPN and ZIP input fuzz matrix against parser AST validators.
  3. KillSwitch simulated failure recovery tests.
- **Artifacts**: `failure-injection-report.xml`, `fuzz-smoke-report.xml` (7-day retention).

---

### Release Gate: Portable Bundle & Release Gate (`.github/workflows/release-gate.yml` & `build-windows.yml`)

- **Purpose**: Deterministic compilation of the signed Windows portable binary package and release asset publishing.
- **Trigger**:
  - `push: tags: ["v*.*.*"]` (`release-gate.yml`)
  - `workflow_dispatch` (`build-windows.yml`)
- **Runner**: `windows-2022`.
- **Permissions**: Top-level `permissions: contents: read`; job-level `permissions: contents: write` strictly scoped to the final release publishing step.
- **Security & Integrity Steps**:
  1. Python locked dependency install (`requirements.lock`) & frozen Bun lockfile (`bun install --frozen-lockfile`)
  2. PyInstaller executable packaging (`python scripts/build_portable.py`)
  3. Download official OpenVPN / sing-box runtimes and verify SHA-256 + GPG detached signatures (`scripts/fetch_components.py`)
  4. Zero-trust smoke test execution on compiled binary (`scripts/smoke_test.py`)
  5. Security manifest and provenance whitelist validation (`scripts/verify_manifest.py`, `scripts/verify_provenance.py`)
  6. Atomic GitHub Release creation (`softprops/action-gh-release@v2`) with portable zip bundle.

---

## 3. Security Controls & Threat Mitigations

| Security Surface | Threat / Vulnerability Vector | CI/CD Defense Implementation |
| :--- | :--- | :--- |
| **Token Permissions** | GITHUB_TOKEN over-privilege / lateral movement | Top-level `permissions: contents: read` on all workflows; write permissions only scoped to tag release step. |
| **Shell Injection** | Unsanitized context expansion (`${{ github.sha }}`) | All context expressions passed via process environment variables (e.g. `COMMIT_SHA: ${{ github.sha }}`). |
| **Credential Persistence** | Leaked git credentials in runner workspace | `actions/checkout@v4` configured with `persist-credentials: false`. |
| **Third-Party Actions** | Action hijacking / supply chain drift | Only pinned official and vetted community actions (`actions/*`, `oven-sh/*`, `dtolnay/*`, `softprops/*`). |
| **Dependency Tampering** | Phantom dependency injection | Flat, hashless `requirements.lock` and `pip install --no-deps` execution model. |
| **Vulnerability Detection** | Known CVEs in transitive dependencies | `pip-audit` runs automatically on every PR and push. |
| **Artifact Exfiltration** | Accidental credential dumping in logs/artifacts | Automated reports contain only JUnit XML test tallies and dependency JSON; no environmental dumps or credentials. |

---

## 4. Cost Governance & Free-Tier Optimization

1. **Standard Runners Only**: Exclusively uses standard GitHub-hosted `ubuntu-latest` and `windows-2022` runners. No larger runners, self-hosted runners, or paid SaaS services.
2. **Linux-First Tier 1**: The high-frequency `ci.yml` runs on `ubuntu-latest` (1x minute consumption) instead of `windows-2022` (2x minute multiplier), cutting monthly free-tier consumption by 50%.
3. **Selective Windows E2E Triggering**: Windows runners are triggered only for explicit VPN/platform path changes or manual dispatch, preventing unnecessary 2x minute burn on simple documentation or frontend edits.
4. **Concurrency Preemption**: `cancel-in-progress: true` automatically cancels obsolete pipeline runs when multiple commits are pushed in quick succession.
5. **Artifact Retention Policy**: Artifact retention is limited to 7 days for test/security reports and 14 days for portable build archives, keeping GitHub storage well within free-tier thresholds.
