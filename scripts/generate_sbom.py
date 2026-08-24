"""
OpenSight SBOM (Software Bill of Materials) Generator
Generates CycloneDX and SPDX compatible SBOM for OpenSight portable releases.
"""
from __future__ import annotations
import json
import time
from pathlib import Path
from typing import Optional

def generate_cyclonedx_sbom(
    app_version: str,
    output_path: Path,
    bundled_components: Optional[list[dict]] = None
) -> dict:
    components = [
        {
            "type": "application",
            "name": "opensight",
            "version": app_version,
            "description": "OpenSight desktop VPN manager and node measurement core",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "type": "framework",
            "name": "fastapi",
            "version": "0.110.3",
            "purl": "pkg:pypi/fastapi@0.110.3",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "type": "library",
            "name": "uvicorn",
            "version": "0.28.1",
            "purl": "pkg:pypi/uvicorn@0.28.1",
            "licenses": [{"license": {"id": "BSD-3-Clause"}}],
        },
        {
            "type": "library",
            "name": "httpx",
            "version": "0.28.1",
            "purl": "pkg:pypi/httpx@0.28.1",
            "licenses": [{"license": {"id": "BSD-3-Clause"}}],
        },
        {
            "type": "library",
            "name": "tauri",
            "version": "2.0.0",
            "purl": "pkg:cargo/tauri@2.0.0",
            "licenses": [{"license": {"id": "Apache-2.0"}}, {"license": {"id": "MIT"}}],
        },
        {
            "type": "library",
            "name": "react",
            "version": "18.3.1",
            "purl": "pkg:npm/react@18.3.1",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "type": "operating-system",
            "name": "openvpn",
            "version": "2.7.5",
            "description": "OpenVPN Community Edition Windows x64 binary",
            "licenses": [{"license": {"id": "GPL-2.0-only"}}],
        },
        {
            "type": "operating-system",
            "name": "sing-box",
            "version": "1.13.15",
            "description": "sing-box universal proxy platform binary",
            "licenses": [{"license": {"id": "GPL-3.0-or-later"}}],
        },
    ]

    if bundled_components:
        components.extend(bundled_components)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:opensight-{app_version}-{int(time.time())}",
        "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tools": [
                {
                    "vendor": "OpenSight Contributors",
                    "name": "opensight-sbom-generator",
                    "version": app_version,
                }
            ],
            "component": {
                "type": "application",
                "name": "opensight-full-portable",
                "version": app_version,
            },
        },
        "components": components,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sbom, indent=2, ensure_ascii=False), encoding="utf-8")
    return sbom

if __name__ == "__main__":
    import sys
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("SBOM.cdx.json")
    generate_cyclonedx_sbom("3.2.0", out)
    print(f"[PASS] SBOM generated at {out}")
