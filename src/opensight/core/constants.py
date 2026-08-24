from typing import Final



APP_NAME: Final[str] = "OpenSight"

APP_VERSION: Final[str] = "3.2.0"

ORGANIZATION_NAME: Final[str] = "OpenSight"

SCORING_VERSION: Final[str] = "1.0"



DEFAULT_DB_NAME: Final[str] = "opensight.db"

DEFAULT_PROFILES_DIR: Final[str] = "profiles"

DEFAULT_DATA_DIR: Final[str] = "data"

DEFAULT_LOGS_DIR: Final[str] = "logs"

DEFAULT_LICENSES_DIR: Final[str] = "licenses"

DEFAULT_OPENVPN_DIR: Final[str] = "openvpn"

DEFAULT_SINGBOX_DIR: Final[str] = "singbox"

SECURITY_MANIFEST_FILE: Final[str] = "SECURITY-MANIFEST.json"

SHA256SUMS_FILE: Final[str] = "SHA256SUMS.txt"



DEFAULT_PROBE_CONCURRENCY: Final[int] = 6

MIN_PROBE_CONCURRENCY: Final[int] = 1

MAX_PROBE_CONCURRENCY: Final[int] = 8



DEFAULT_DNS_TIMEOUT_SEC: Final[float] = 2.5

DEFAULT_TCP_TIMEOUT_SEC: Final[float] = 3.5

DEFAULT_DIRECT_HTTPS_TIMEOUT_SEC: Final[float] = 4.0

DEFAULT_TCP_SAMPLE_COUNT: Final[int] = 3



SUCCESS_COOLDOWN_SEC: Final[int] = 300

FAILURE_COOLDOWN_SEC: Final[int] = 120

PROBE_COOLDOWN_JITTER_SEC: Final[float] = 30.0
PROBE_FAILURE_BACKOFF_CAP_SEC: Final[int] = 900
PROBE_WORKER_START_JITTER_SEC: Final[float] = 0.8

DEFAULT_IP_CHECKPOINT_INTERVAL_SEC: Final[float] = 60.0



DEFAULT_BASELINE_HTTPS_TARGETS: Final[tuple[str, ...]] = (

    "https://www.aliyun.com",

    "https://www.cloudflare.com/cdn-cgi/trace",

    "https://www.google.com/generate_204",

    "https://www.microsoft.com",

)



DEFAULT_DOMESTIC_PUBLIC_IP_SERVICES: Final[tuple[str, ...]] = (

    "https://myip.ipip.net",

)

DEFAULT_OVERSEAS_PUBLIC_IP_SERVICES: Final[tuple[str, ...]] = (

    "https://icanhazip.com",

    "https://api.ipify.org",

    "https://checkip.amazonaws.com",

)

DEFAULT_PUBLIC_IP_SERVICES: Final[tuple[str, ...]] = DEFAULT_DOMESTIC_PUBLIC_IP_SERVICES



CONFIDENCE_HIGH: Final[str] = "高"

CONFIDENCE_MEDIUM: Final[str] = "中"

CONFIDENCE_LOW: Final[str] = "低"

CONFIDENCE_INSUFFICIENT: Final[str] = "数据不足"

CONFIDENCE_UNAVAILABLE: Final[str] = "不可用"



CATEGORY_RECOMMENDED: Final[str] = "综合推荐"

CATEGORY_WEB: Final[str] = "网页浏览推荐"

CATEGORY_VIDEO: Final[str] = "视频浏览推荐"

CATEGORY_STABLE: Final[str] = "最稳定"

CATEGORY_LOW_LATENCY: Final[str] = "最低延迟"

CATEGORY_UNAVAILABLE: Final[str] = "当前不可用"

CATEGORY_INSUFFICIENT_DATA: Final[str] = "数据不足"



VIEW_MODE_RECOMMENDED: Final[str] = "综合推荐"

VIEW_MODE_WEB: Final[str] = "网页浏览"

VIEW_MODE_VIDEO: Final[str] = "视频浏览"

VIEW_MODE_STABILITY: Final[str] = "稳定性"

VIEW_MODE_LATENCY: Final[str] = "最低延迟"

VIEW_MODE_COUNTRY: Final[str] = "国家"

VIEW_MODE_NAME: Final[str] = "节点名称"

VIEW_MODE_RECENT: Final[str] = "最近测速"



THEME_SYSTEM: Final[str] = "跟随系统"

THEME_LIGHT: Final[str] = "浅色"

THEME_DARK: Final[str] = "深色"

THEME_KEY_SYSTEM: Final[str] = "system"

THEME_KEY_LIGHT: Final[str] = "light"

THEME_KEY_DARK: Final[str] = "dark"



STAGE_INITIALIZING: Final[str] = "初始化"

STAGE_CHECKING_IP: Final[str] = "检测公网IP"

STAGE_DNS_RESOLVING: Final[str] = "DNS 解析"

STAGE_TCP_PROBING: Final[str] = "TCP 探测"

STAGE_BASELINE_HTTPS: Final[str] = "直连网络体验"

STAGE_COMPLETED: Final[str] = "完成"

STAGE_PAUSED: Final[str] = "已暂停"

STAGE_STOPPED: Final[str] = "已停止"



ERR_NONE: Final[str] = "NONE"

ERR_DNS_TIMEOUT: Final[str] = "DNS_TIMEOUT"

ERR_DNS_FAILED: Final[str] = "DNS_FAILED"

ERR_TCP_TIMEOUT: Final[str] = "TCP_TIMEOUT"

ERR_TCP_REFUSED: Final[str] = "TCP_REFUSED"

ERR_TCP_NETWORK_ERROR: Final[str] = "TCP_NETWORK_ERROR"

ERR_HTTPS_TIMEOUT: Final[str] = "HTTPS_TIMEOUT"

ERR_HTTPS_FAILED: Final[str] = "HTTPS_FAILED"

ERR_IP_DRIFT_DETECTED: Final[str] = "IP_DRIFT_DETECTED"

ERR_CANCELLED: Final[str] = "CANCELLED"



# 固化的官方上游真实发布 SHA-256 校验基准

OPENVPN_VERSION: Final[str] = "2.7.5"

OPENVPN_MSI_NAME: Final[str] = f"OpenVPN-{OPENVPN_VERSION}-I001-amd64.msi"

OPENVPN_MSI_SHA256: Final[str] = "20a9b2831cc3be26c250caf60891c230f3bf3e1e7bd6e17b4e182f166026377a"

OPENVPN_MSI_SIZE: Final[int] = 5865472



SINGBOX_VERSION: Final[str] = "1.13.15"

SINGBOX_ZIP_SHA256: Final[str] = "599b296f6e57511d36d2a6f3011aed1a86fa98418578bbb06bd6dc241b5d8877"
