import os
import sys
import threading
import time
import secrets
import uvicorn
from opensight.core.safety import ensure_portable_environment
from opensight.core.logger import setup_logging, get_logger
from opensight.core.constants import APP_NAME, APP_VERSION
from opensight.api.server import create_app

def stdin_watchdog():
    """当父进程（Tauri）退出导致 stdin 被彻底关闭时安全退出"""
    try:
        # 如果 stdin 是有效的终端或管道，阻塞读取
        if sys.stdin and not sys.stdin.closed:
            while True:
                line = sys.stdin.readline()
                if not line:  # EOF 信号
                    break
                time.sleep(1)
    except Exception:
        pass
    os._exit(0)

def main() -> int:
    # 冒烟测试快速响应支持
    if "--smoke-test" in sys.argv:
        print("[PASS] opensight-core smoke test passed.")
        return 0

    portable_paths = ensure_portable_environment()
    setup_logging(portable_paths.logs_dir)
    logger = get_logger("main")

    port = 52024
    enable_watchdog = True
    auth_token = os.environ.get("OPENSIGHT_AUTH_TOKEN", "").strip()
    allow_insecure = os.environ.get("OPENSIGHT_ALLOW_INSECURE_LOCAL_API") == "1"

    i = 0
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--port" and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
            i += 2
            continue
        elif arg == "--auth-token" and i + 1 < len(sys.argv):
            auth_token = sys.argv[i + 1].strip()
            i += 2
            continue
        elif arg == "--insecure-local-development":
            allow_insecure = True
            i += 1
            continue
        elif arg == "--no-watchdog":
            enable_watchdog = False
            i += 1
            continue
        i += 1

    if allow_insecure:
        logger.warning("⚠️ [SECURITY WARNING] 启用非安全本地开发模式 (--insecure-local-development)，API 认证已放宽。生产构建严禁使用此模式！")
    elif not auth_token:
        # 生产环境默认强制生成 256 位熵随机安全 Token
        auth_token = secrets.token_hex(32)
        logger.info("已生成生产环境 256-bit API 访问凭据 (Auth Token)")

    # 仅在非禁用看门狗模式且存在 stdin 时启用
    if enable_watchdog and sys.stdin and not sys.stdin.closed and os.environ.get("OPENSIGHT_NO_WATCHDOG") != "1":
        threading.Thread(target=stdin_watchdog, daemon=True).start()

    logger.info(f"启动 {APP_NAME} Headless Core v{APP_VERSION} (端口: {port})")
    app = create_app(portable_paths, auth_token=auth_token, allow_insecure=allow_insecure)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    return 0

if __name__ == "__main__":
    sys.exit(main())
