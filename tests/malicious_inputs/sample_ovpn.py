# OpenSight Malicious OVPN and Configuration Test Fixtures

MALICIOUS_OVPN_CASES = {
    "up_directive": """
client
dev tun
proto udp
remote 198.51.100.1 1194
script-security 2
up /tmp/malicious_payload.sh
""",
    "down_directive": """
client
dev tun
proto udp
remote 198.51.100.1 1194
down "powershell.exe -Command Invoke-Expression"
""",
    "script_security": """
client
proto tcp
remote 198.51.100.1 443
script-security 3
""",
    "plugin_injection": """
client
proto udp
remote 198.51.100.1 1194
plugin /usr/lib/openvpn/plugins/evil.so
""",
    "management_interface": """
client
proto udp
remote 198.51.100.1 1194
management 0.0.0.0 9999
""",
    "management_client": """
client
proto tcp
remote 198.51.100.1 443
management-client
""",
    "client_connect_hook": """
client
proto udp
remote 198.51.100.1 1194
client-connect /usr/local/bin/evil_hook.sh
""",
    "client_disconnect_hook": """
client
proto udp
remote 198.51.100.1 1194
client-disconnect "cmd.exe /c calc.exe"
""",
    "tls_verify_hook": """
client
proto tcp
remote 198.51.100.1 443
tls-verify /tmp/verify.py
""",
    "auth_user_pass_verify": """
client
proto tcp
remote 198.51.100.1 443
auth-user-pass-verify /tmp/auth.sh via-env
""",
    "ipchange_hook": """
client
proto udp
remote 198.51.100.1 1194
ipchange /tmp/ipchange.sh
""",
    "chroot_directive": """
client
proto udp
remote 198.51.100.1 1194
chroot /var/empty
""",
    "cd_directive": """
client
proto udp
remote 198.51.100.1 1194
cd /etc/shadow
""",
    "writepid_directive": """
client
proto udp
remote 198.51.100.1 1194
writepid /etc/cron.d/evil_cron
""",
    "config_include_escape": """
client
proto tcp
remote 198.51.100.1 443
config /etc/openvpn/evil.conf
""",
    "hidden_in_connection_block": """
client
proto tcp
<connection>
remote 198.51.100.1 443 tcp
up /tmp/hidden_evil.sh
</connection>
""",
    "hidden_in_connection_case_variations": """
client
proto udp
<CONNECTION>
remote 198.51.100.1 1194 udp
SCRIPT-SECURITY 2
PLUGIN /tmp/evil.dll
</CONNECTION>
""",
    "unauthorized_custom_tag": """
client
proto tcp
<script>
alert('xss');
</script>
remote 198.51.100.1 443
""",
    "unauthorized_xml_injection": """
client
proto udp
<?xml version="1.0"?>
<!DOCTYPE evil [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<evil_tag>
test
</evil_tag>
remote 198.51.100.1 1194
""",
    "case_variation_up": """
client
proto udp
remote 198.51.100.1 1194
uP /bin/sh
""",
    "trailing_comment_bypass_attempt": """
client
proto tcp
remote 198.51.100.1 443
up /evil/path.sh # this is a comment
""",
    "semicolon_comment_bypass_attempt": """
client
proto tcp
remote 198.51.100.1 443
down /evil/down.sh ; inline comment
""",
}

VALID_OVPN_PROFILES = {
    "standard_protonvpn": """
client
dev tun
proto udp
remote jp-free-01.protonvpn.net 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA512
verb 3
redirect-gateway def1
block-outside-dns
block-ipv6
<ca>
-----BEGIN CERTIFICATE-----
MIIB/zCCAaWgAwIBAgIUQ4
-----END CERTIFICATE-----
</ca>
<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
e1a4b5c6
-----END OpenVPN Static key V1-----
</tls-crypt>
""",
    "multi_remote_tcp": """
client
dev tun
proto tcp
remote us-free-02.protonvpn.net 443
remote us-free-02.protonvpn.net 8443
resolv-retry infinite
nobind
auth-user-pass
compress lz4
redirect-gateway def1
<connection>
remote nl-free-01.protonvpn.net 443 tcp
</connection>
<connection>
remote nl-free-02.protonvpn.net 8443 tcp
</connection>
""",
    "with_comments_and_whitespace": """
# ProtonVPN Configuration File
; Alternative comment style
client
dev tun

proto udp # protocol setting
remote ch-01.protonvpn.net 1194 ; default port

nobind
persist-key
persist-tun
fast-io
""",
}
