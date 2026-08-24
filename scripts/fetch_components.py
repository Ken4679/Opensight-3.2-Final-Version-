from __future__ import annotations
import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))

from opensight.core.constants import (
    OPENVPN_MSI_NAME, OPENVPN_MSI_SHA256, OPENVPN_MSI_SIZE, OPENVPN_VERSION,
    SINGBOX_VERSION, SINGBOX_ZIP_SHA256
)

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

COMPONENTS = {
    "openvpn": {
        "version": OPENVPN_VERSION,
        "source_url": f"https://build.openvpn.net/downloads/releases/{OPENVPN_MSI_NAME}",
        "source_domain": "build.openvpn.net",
        "sha256": OPENVPN_MSI_SHA256,
        "size": OPENVPN_MSI_SIZE,
        "dir": "openvpn",
        "exe": "openvpn.exe",
    },
    "sing-box": {
        "version": SINGBOX_VERSION,
        "source_url": f"https://github.com/SagerNet/sing-box/releases/download/v{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION}-windows-amd64.zip",
        "source_domain": "github.com",
        "archive_sha256": SINGBOX_ZIP_SHA256,
        "dir": "singbox",
        "exe": "sing-box.exe",
    },
}

ALLOWED_DOMAINS = frozenset({
    "build.openvpn.net", "openvpn.net", "github.com",
    "objects.githubusercontent.com", "release-assets.githubusercontent.com",
})

def download(url: str, path: Path) -> str:
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.split(":")[0].lower()
    if parsed.scheme != "https" or domain not in ALLOWED_DOMAINS:
        raise RuntimeError(f"Disallowed URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "OpenSight-Builder/3.1"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        final = urllib.parse.urlparse(resp.geturl())
        final_domain = final.netloc.split(":")[0].lower()
        if final.scheme != "https" or final_domain not in ALLOWED_DOMAINS:
            raise RuntimeError(f"Disallowed redirect target: {resp.geturl()}")
        with path.open("wb") as fh:
            shutil.copyfileobj(resp, fh, 1024 * 1024)
    return resp.geturl()

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().lower()

def verify_pe(path: Path) -> None:
    if not path.is_file() or path.stat().st_size < 1024 * 1024:
        raise RuntimeError(f"Invalid runtime executable: {path}")
    with path.open("rb") as fh:
        if fh.read(2) != b"MZ":
            raise RuntimeError(f"Not a Windows PE executable: {path}")

def run_version(path: Path, args: list[str], expected: str, label: str) -> None:
    p = subprocess.run(
        [str(path), *args], cwd=str(path.parent), stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, timeout=30, check=False,
    )
    if p.returncode != 0 or expected not in (p.stdout or ""):
        raise RuntimeError(f"{label} version check failed: exit={p.returncode}\n{p.stdout}")

def verify_openvpn(msi: Path, meta: dict) -> None:
    if msi.stat().st_size != meta["size"]:
        raise RuntimeError(f"Unexpected OpenVPN MSI size: {msi.stat().st_size}")
    actual = sha256(msi)
    if actual != meta["sha256"]:
        raise RuntimeError(f"OpenVPN MSI SHA-256 mismatch: expected {meta['sha256']}, got {actual}")
    print(f"[PASS] OpenVPN 官方安装包 SHA-256 强校验通过: {actual}")

def extract_openvpn(msi: Path, destination: Path, work: Path) -> Path:
    root = work / "openvpn-msi"
    root.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["msiexec.exe", "/a", str(msi), f"TARGETDIR={root}", "/qn", "/norestart"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180,
    )
    if r.returncode != 0:
        raise RuntimeError(f"OpenVPN MSI extraction failed: {r.returncode}\n{r.stderr}")
    candidates = list(root.rglob("openvpn.exe"))
    if not candidates:
        raise RuntimeError("openvpn.exe not found inside the OpenVPN MSI")
    exe = next((p for p in candidates if p.parent.name.lower() == "bin"), candidates[0])
    destination.mkdir(parents=True, exist_ok=True)
    for item in exe.parent.iterdir():
        if item.is_file() and not item.is_symlink():
            shutil.copy2(item, destination / item.name)
    target = destination / "openvpn.exe"
    verify_pe(target)
    return target

def extract_singbox(archive: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            raw_name = info.filename.replace("\\", "/")
            parts = Path(raw_name).parts
            if not parts or any(p in ("", ".", "..") for p in parts) or Path(raw_name).is_absolute():
                raise RuntimeError(f"Unsafe archive member: {info.filename}")
            if info.is_dir():
                continue
            name = parts[-1]
            if name == "sing-box.exe" or name.lower().endswith(".dll") or name.lower().startswith("license"):
                target = destination / name
                with zf.open(info) as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
    exe = destination / "sing-box.exe"
    verify_pe(exe)
    return exe

def fetch_and_install_components(destination_dir: Path) -> None:
    if sys.platform != "win32":
        raise RuntimeError("Runtime bundling is Windows-only")
    destination_dir = destination_dir.resolve()
    licenses = destination_dir / "licenses"
    licenses.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="opensight-components-") as td:
        work = Path(td)
        ov = COMPONENTS["openvpn"]
        msi_name = OPENVPN_MSI_NAME
        msi = work / msi_name
        download(ov["source_url"], msi)
        verify_openvpn(msi, ov)
        ov_dir = destination_dir / ov["dir"]
        ov_exe = extract_openvpn(msi, ov_dir, work)
        bundled_msi = ov_dir / msi_name
        shutil.copy2(msi, bundled_msi)
        run_version(ov_exe, ["--version"], ov["version"], "OpenVPN")
        (licenses / "LICENSE-openvpn.txt").write_text(
            "OpenVPN Community Edition; see the included upstream licensing files and https://openvpn.net/\n",
            encoding="utf-8",
        )

        sb = COMPONENTS["sing-box"]
        archive = work / "sing-box.zip"
        download(sb["source_url"], archive)
        actual = sha256(archive)
        if actual != sb["archive_sha256"]:
            raise RuntimeError(f"sing-box archive SHA-256 mismatch: expected {sb['archive_sha256']}, got {actual}")
        print(f"[PASS] sing-box 官方压缩包 SHA-256 校验通过: {actual}")
        sb_exe = extract_singbox(archive, destination_dir / sb["dir"])
        run_version(sb_exe, ["version"], sb["version"], "sing-box")
        license_candidates = list((destination_dir / sb["dir"]).glob("LICENSE*"))
        if license_candidates:
            shutil.copy2(license_candidates[0], licenses / "LICENSE-sing-box.txt")
        else:
            (licenses / "LICENSE-sing-box.txt").write_text(
                "sing-box: see https://github.com/SagerNet/sing-box/blob/main/LICENSE\n",
                encoding="utf-8",
            )

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dest", type=Path, default=ROOT_DIR / "dist" / "OpenSight")
    args = parser.parse_args()
    try:
        fetch_and_install_components(args.dest)
        print("[PASS] OpenVPN and sing-box runtimes are bundled and runnable.")
    except Exception as exc:
        print(f"[ERROR] Runtime component setup failed: {exc}", file=sys.stderr)
        sys.exit(1)
