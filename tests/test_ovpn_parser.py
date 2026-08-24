from opensight.core.parser import OvpnParser

SAMPLE = "client\nproto tcp\nremote jp-free-01.protonvpn.net 443\nremote jp-free-01.protonvpn.net 1194 tcp\n"

def test_ovpn_parser_remotes():
    p = OvpnParser.parse_text(SAMPLE, filename="jp-free-01.tcp.ovpn")
    assert p.country_code == "JP"
    assert len(p.remotes) == 2
    assert p.remotes[0].port == 443
    assert p.remotes[1].port == 1194