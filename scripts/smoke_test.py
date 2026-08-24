import argparse
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

EXPECTED_OPENVPN_VERSION = "2.7.5"
EXPECTED_SINGBOX_VERSION = "1.13.15"

def _run_version(exe: Path, args: list[str], expected: str, label: str) -> bool:
    if not exe.is_file():
        print(f"[FAIL] Missing bundled {label}: {exe}", file=sys.stderr)
        return False
    try:
        proc = subprocess.run(
            [str(exe), *args], cwd=str(exe.parent), timeout=20,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
    except Exception as exc:
        print(f"[FAIL] Could not execute bundled {label}: {exc}", file=sys.stderr)
        return False
    output = proc.stdout or ""
    if proc.returncode != 0 or expected not in output:
        print(f"[FAIL] {label} runtime check failed. exit={proc.returncode}\n{output}", file=sys.stderr)
        return False
    print(f"[PASS] Bundled {label} {expected} runtime check passed.")
    return True

def run_smoke_test(exe_path: Path) -> bool:
    print(f"=== 开始对可执行文件执行严格冒烟测试: {exe_path} ===")
    if not exe_path.is_file():
        print(f"[FAIL] 目标文件不存在: {exe_path}", file=sys.stderr)
        return False

    size = exe_path.stat().st_size
    print(f"产物大小: {size} 字节 ({round(size / 1024 / 1024, 2)} MB)")
    if size < 2 * 1024 * 1024:
        print("[FAIL] 产物体积异常过小 (< 2MB)，判定为非有效独立运行时！", file=sys.stderr)
        return False

    if sys.platform == "win32":
        with open(exe_path, "rb") as f:
            magic = f.read(2)
            if magic != b"MZ":
                print("[FAIL] 产物非有效 Windows PE 二进制 (缺少 MZ 头)！", file=sys.stderr)
                return False
        print("[PASS] PE 文件头校验通过。")

    bundle_root = exe_path.parent
    if not _run_version(bundle_root / "openvpn" / "openvpn.exe", ["--version"], EXPECTED_OPENVPN_VERSION, "OpenVPN"):
        return False
    if not _run_version(bundle_root / "singbox" / "sing-box.exe", ["version"], EXPECTED_SINGBOX_VERSION, "sing-box"):
        return False

    # 验证 Python 核心 headless 服务的冒烟启动
    core_candidates = [
        bundle_root / "opensight-core" / "opensight-core.exe",
        bundle_root / "opensight-core.exe",
    ]
    core_exe = next((c for c in core_candidates if c.is_file()), None)
    if not core_exe:
        print("[FAIL] 未找到 opensight-core 核心二进制！", file=sys.stderr)
        return False

    print("拉起 Headless Core 进程执行 API 冒烟自检...")
    env = os.environ.copy()
    env["OPENSIGHT_NO_WATCHDOG"] = "1"
    test_port = 52099
    proc = None
    try:
        proc = subprocess.Popen(
            [str(core_exe), "--port", str(test_port), "--no-watchdog"],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        # 等待服务就绪并探活
        ok = False
        for _ in range(40):
            time.sleep(0.25)
            if proc.poll() is not None:
                break
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{test_port}/api/health", timeout=1) as resp:
                    if resp.status == 200:
                        ok = True
                        break
            except Exception:
                continue

        if not ok:
            stderr_out = proc.stderr.read() if proc.stderr else ""
            print(f"[FAIL] Core API 服务启动失败/超时退出 (代码: {proc.poll()}):\n{stderr_out}", file=sys.stderr)
            return False

        print("[PASS] Core API Health Check (127.0.0.1) 响应 200 OK！")
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()

    print("[PASS] 真实可执行文件与核心运行时冒烟测试全部通过！")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("exe_path", type=Path)
    args = parser.parse_args()
    if not run_smoke_test(args.exe_path):
        sys.exit(1)
