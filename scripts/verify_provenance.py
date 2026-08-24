import argparse
import json
import sys
import urllib.parse
from pathlib import Path

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

_ALLOWED_DOMAINS = {
    "build.openvpn.net", "swupdate.openvpn.org",
    "openvpn.net", "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"
}

def verify_provenance(staging_dir: Path) -> bool:
    manifest_path = staging_dir / "SECURITY-MANIFEST.json"
    if not manifest_path.exists():
        return False
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    for art in data.get("artifacts", []):
        url = art.get("source_url", "")
        if art.get("opensight_owned", False) and url.startswith("build://"):
            continue
        p = urllib.parse.urlparse(url)
        if p.scheme != "https" or p.netloc.split(":")[0].lower() not in _ALLOWED_DOMAINS:
            print(f"[FAIL] 组件来源域名非法不在白名单内: {url}", file=sys.stderr)
            return False
    print("[PASS] 组件来源域名白名单校验通过！")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("staging_dir", type=Path)
    args = parser.parse_args()
    if not verify_provenance(args.staging_dir):
        sys.exit(1)
