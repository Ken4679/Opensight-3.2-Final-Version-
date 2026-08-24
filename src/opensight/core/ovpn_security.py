import re
from typing import Final, Tuple, Set

class SecurityViolationError(Exception):
    pass

# 严格禁止的危险指令集
FORBIDDEN_DIRECTIVES: Final[Set[str]] = {
    "up", "down", "route-up", "route-pre-down", "plugin",
    "script-security", "config", "include", "management",
    "management-client", "client-connect", "client-disconnect",
    "tls-verify", "learn-address", "auth-user-pass-verify",
    "ipchange", "setenv", "chroot", "cd", "writepid",
    "socks-proxy", "http-proxy", "management-hold",
}

# 明确允许的安全基础指令白名单
ALLOWED_DIRECTIVES: Final[Set[str]] = {
    "client", "dev", "proto", "remote", "port", "resolv-retry",
    "nobind", "persist-key", "persist-tun", "remote-cert-tls",
    "auth", "cipher", "data-ciphers", "data-ciphers-fallback",
    "verb", "mute", "auth-user-pass", "explicit-exit-notify",
    "topology", "pull", "fast-io", "comp-lzo", "compress",
    "tls-client", "key-direction", "auth-nocache", "reneg-sec",
    "hand-window", "tran-window", "ping", "ping-restart", "inactive",
    "connect-retry", "connect-timeout", "mute-replay-warnings",
    "redirect-gateway", "block-outside-dns", "block-ipv6"
}

ALLOWED_TAG_BLOCKS: Final[Set[str]] = {
    "ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "connection"
}

def validate_ovpn_security(text: str, source_name: str = "profile.ovpn") -> Tuple[bool, str]:
    """
    深度递归与块内解析的安全策略验证器。
    杜绝通过 <tag> 或 <connection> 块绕过顶层指令过滤的漏洞。
    """
    in_tag = None
    
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        clean = raw_line.strip()
        if not clean:
            continue
            
        # 处理闭合标签
        if in_tag:
            if clean.lower().startswith(f"</{in_tag}>"):
                in_tag = None
                continue
            # 在 <connection> 块内部，依然必须严格执行指令验证
            if in_tag == "connection":
                sub_clean = re.split(r"\s+[#;]", clean, maxsplit=1)[0].strip()
                if sub_clean:
                    tokens = sub_clean.split()
                    directive = tokens[0].lower()
                    if directive in FORBIDDEN_DIRECTIVES:
                        return False, f"在 <connection> 块内检测到禁止指令 '{directive}' (第 {line_no} 行, 来源: {source_name})"
            continue

        # 处理开放标签
        if clean.startswith("<") and clean.endswith(">") and not clean.startswith("</"):
            tag_name = clean[1:-1].strip().split()[0].lower()
            if tag_name not in ALLOWED_TAG_BLOCKS:
                return False, f"检测到非法配置块 <{tag_name}> (第 {line_no} 行, 来源: {source_name})"
            in_tag = tag_name
            continue

        # 忽略注释
        if clean.startswith("#") or clean.startswith(";"):
            continue

        clean = re.split(r"\s+[#;]", clean, maxsplit=1)[0].strip()
        tokens = clean.split()
        if not tokens:
            continue

        directive = tokens[0].lower()
        if directive in FORBIDDEN_DIRECTIVES:
            return False, f"检测到禁止的危险指令 '{directive}' (第 {line_no} 行, 来源: {source_name})"

    return True, "验证通过"
