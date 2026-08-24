import pytest
from opensight.core.ovpn_security import validate_ovpn_security
from opensight.core.parser import OvpnParser, ParseError

SAFE_PROFILE = "client\nproto tcp\nremote jp.protonvpn.net 443\n"
DANGEROUS_PROFILE = "client\nproto tcp\nscript-security 2\nup /tmp/malicious.sh\nremote jp.protonvpn.net 443\n"

def test_ovpn_security_blocks_dangerous_directives():
    is_safe, msg = validate_ovpn_security(SAFE_PROFILE)
    assert is_safe

    is_safe, msg = validate_ovpn_security(DANGEROUS_PROFILE)
    assert not is_safe
    assert "script-security" in msg

def test_parser_rejects_dangerous_profile():
    with pytest.raises(ParseError, match="安全策略拦截"):
        OvpnParser.parse_text(DANGEROUS_PROFILE, filename="unsafe.ovpn")