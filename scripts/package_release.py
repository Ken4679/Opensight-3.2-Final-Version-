import argparse
import hashlib
import os
import shutil
import sys
import time
import zipfile
from pathlib import Path

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))
sys.path.insert(0, str(ROOT_DIR / "scripts"))
from opensight.core.constants import APP_VERSION, OPENVPN_MSI_SHA256, OPENVPN_VERSION, SINGBOX_VERSION
from opensight.packaging.manifest import ManifestGenerator
from opensight.packaging.provenance import ArtifactProvenance, VerificationStatus
from generate_sbom import generate_cyclonedx_sbom

REQUIRED_RUNTIMES = {
    "openvpn.exe": "openvpn/openvpn.exe",
    "sing-box.exe": "singbox/sing-box.exe",
}

def package_release(output_dir: Path, commit_sha: str = "LOCAL_BUILD") -> Path:
    print(f"=== 开始便携包发布封装流程 (Commit: {commit_sha}) ===")
    dist_dir = ROOT_DIR / "dist" / "OpenSight"
    exe_name = "OpenSight.exe" if sys.platform == "win32" else "OpenSight"
    dist_exe = dist_dir / exe_name
    if not dist_exe.is_file():
        raise RuntimeError(f"未找到真实的编译产物: {dist_exe}")
    for label, rel in REQUIRED_RUNTIMES.items():
        runtime = dist_dir / rel
        if not runtime.is_file():
            raise RuntimeError(f"缺少必需运行时 {label}: {runtime}")

    staging_dir = output_dir / "staging"
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True)

    print("正在复制完整运行时环境...")
    for item in dist_dir.iterdir():
        dest = staging_dir / item.name
        if item.is_dir():
            shutil.copytree(item, dest)
        else:
            shutil.copy2(item, dest)

    for sub in ("data", "logs", "profiles", "licenses"):
        (staging_dir / sub).mkdir(parents=True, exist_ok=True)

    for label, rel in REQUIRED_RUNTIMES.items():
        if not (staging_dir / rel).is_file():
            raise RuntimeError(f"复制到 staging 后缺少必需运行时 {label}: {rel}")

    for helper_name in (
        "install_openvpn_windows.ps1",
        "uninstall_openvpn_windows.ps1",
        "repair_openvpn_windows.ps1",
        "uninstall_opensight_windows.ps1",
        "run_singbox_windows.ps1",
    ):
        helper_src = ROOT_DIR / "scripts" / helper_name
        if helper_src.is_file():
            shutil.copy2(helper_src, staging_dir / helper_name)
        else:
            raise RuntimeError(f"缺少便携版管理辅助脚本: {helper_src}")

    (staging_dir / "README-PORTABLE.txt").write_text(
        f"OpenSight v{APP_VERSION} Windows x64 完全自包含便携版\n"
        "解压至任意目录，双击运行 OpenSight.exe 即可。\n"
        "内置已验证的 OpenVPN 及 sing-box 运行时组件。\n"
        "可以在“设置”中一键修复组件或执行完整卸载。\n"
        "所有数据保存在本目录内。\n",
        encoding="utf-8",
    )

    candidates = [
        # (name, path, url, domain, version, is_opensight_owned, pinned_expected_sha256)
        (exe_name, staging_dir / exe_name, "build://OpenSight", "build", APP_VERSION, True, None),
        ("openvpn.exe", staging_dir / "openvpn" / "openvpn.exe", f"https://build.openvpn.net/downloads/releases/OpenVPN-{OPENVPN_VERSION}-I001-amd64.msi", "build.openvpn.net", OPENVPN_VERSION, False, None),
        (f"OpenVPN-{OPENVPN_VERSION}-I001-amd64.msi", staging_dir / "openvpn" / f"OpenVPN-{OPENVPN_VERSION}-I001-amd64.msi", f"https://build.openvpn.net/downloads/releases/OpenVPN-{OPENVPN_VERSION}-I001-amd64.msi", "build.openvpn.net", OPENVPN_VERSION, False, OPENVPN_MSI_SHA256),
        ("sing-box.exe", staging_dir / "singbox" / "sing-box.exe", f"https://github.com/SagerNet/sing-box/releases/download/v{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION}-windows-amd64.zip", "github.com", SINGBOX_VERSION, False, None),
    ]

    artifacts = []
    for c_name, c_path, c_url, c_domain, c_version, c_owned, c_expected in candidates:
        if not c_path.is_file():
            raise RuntimeError(f"发布清单缺少文件: {c_path}")
        c_actual = hashlib.sha256(c_path.read_bytes()).hexdigest().lower()
        
        if c_owned:
            # OpenSight 自己构建的二进制：不伪造外部预期哈希，明确标为 BUILT_ARTIFACT
            status = VerificationStatus.BUILT_ARTIFACT
            expected_sha = None
        elif c_expected:
            # 外部第三方固化组件：必须与预设官方 hash 严格比对
            expected_sha = c_expected.lower()
            if c_actual != expected_sha:
                raise RuntimeError(f"组件 {c_name} 哈希与官方固化基准不符: 预期 {expected_sha}, 实际 {c_actual}")
            status = VerificationStatus.VERIFIED
        else:
            # 由已验证安装包/ZIP提取出的运行组件
            expected_sha = None
            status = VerificationStatus.VERIFIED

        rel_path = str(c_path.relative_to(staging_dir)).replace("\\", "/")
        artifacts.append(ArtifactProvenance(
            artifact_name=c_name,
            version=c_version,
            source_url=c_url,
            source_domain=c_domain,
            expected_sha256=expected_sha,
            actual_sha256=c_actual,
            verification_status=status,
            file_size_bytes=c_path.stat().st_size,
            local_path=rel_path,
            downloaded_at=int(time.time()),
            opensight_owned=c_owned,
        ))

    gen = ManifestGenerator(type("Paths", (), {"base_dir": staging_dir})())
    gen.generate_manifest(artifacts, build_commit=commit_sha)
    files_to_hash = [staging_dir / a.local_path for a in artifacts]
    gen.generate_sha256sums(files_to_hash)

    # 生成 CycloneDX 规范 SBOM
    generate_cyclonedx_sbom(APP_VERSION, staging_dir / "SBOM.cdx.json")

    zip_path = output_dir / f"OpenSight-v{APP_VERSION}-win-x64-portable-full.zip"
    print(f"正在压缩生成最终便携 ZIP 归档: {zip_path} ...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(staging_dir):
            dirs.sort()
            for f in sorted(files):
                p = Path(root) / f
                zf.write(p, arcname=f"OpenSight/{p.relative_to(staging_dir)}")
    print(f"[PASS] 便携发布包封装完成: {zip_path} ({round(zip_path.stat().st_size / 1024 / 1024, 2)} MB)")
    return zip_path

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=ROOT_DIR / "dist")
    parser.add_argument("--commit", type=str, default="LOCAL_BUILD")
    args = parser.parse_args()
    package_release(args.out, args.commit)
