import os
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

def create_valid_png(width: int, height: int) -> bytes:
    """Fallback icon for environments where the real project icon cannot be converted."""
    raw_rows = []
    for _ in range(height):
        row = bytearray([0])
        for _ in range(width):
            row.extend([37, 99, 235, 255])
        raw_rows.append(bytes(row))
    compressed_data = zlib.compress(b"".join(raw_rows), level=9)
    png = bytearray(b"\x89PNG\r\n\x1a\n")
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    png.extend(struct.pack(">I", len(ihdr)) + b"IHDR" + ihdr + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr) & 0xffffffff))
    png.extend(struct.pack(">I", len(compressed_data)) + b"IDAT" + compressed_data + struct.pack(">I", zlib.crc32(b"IDAT" + compressed_data) & 0xffffffff))
    png.extend(struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xffffffff))
    return bytes(png)

def create_valid_ico(png_data: bytes, width: int = 32, height: int = 32) -> bytes:
    header = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack("<BBBBHHII", width if width < 256 else 0, height if height < 256 else 0, 0, 0, 1, 32, len(png_data), 22)
    return header + entry + png_data

def convert_svg_to_ico(svg_path: Path, target_ico: Path) -> bool:
    try:
        import cairosvg  # type: ignore
        cairosvg.svg2png(url=str(svg_path), write_to=str(target_ico.with_suffix('.png')), output_width=256, output_height=256)
        from PIL import Image  # type: ignore
        png_path = target_ico.with_suffix('.png')
        with Image.open(png_path) as image:
            image.convert('RGBA').save(target_ico, format='ICO', sizes=[(256,256),(128,128),(64,64),(32,32),(16,16)])
        png_path.unlink(missing_ok=True)
        return target_ico.is_file()
    except Exception:
        pass
    for command in ('magick', 'convert'):
        try:
            subprocess.run([command, str(svg_path), str(target_ico)], check=True)
            return target_ico.is_file()
        except Exception:
            continue
    return False

def ensure_tauri_icon(root: Path):
    icon_dir = root / 'src-tauri' / 'icons'
    icon_dir.mkdir(parents=True, exist_ok=True)
    try:
        from generate_icons import generate_all_icons  # type: ignore
        generate_all_icons(root)
        print(f'[PASS] 已完整生成/同步多分辨率应用图标集至: {icon_dir}')
    except Exception as e:
        target_ico = icon_dir / 'icon.ico'
        source_ico = root / 'opensight.ico'
        if source_ico.is_file():
            shutil.copy2(source_ico, target_ico)
            print(f'[PASS] 使用项目真实 ICO 图标: {source_ico}')
        else:
            target_ico.write_bytes(create_valid_ico(create_valid_png(32, 32), 32, 32))
            print(f'[WARN] 兜底生成临时 ICO: {target_ico} (err: {e})')

def build():
    root = Path(__file__).resolve().parent.parent
    dist = root / "dist" / "OpenSight"
    dist_web = root / "dist-web"

    dist.mkdir(parents=True, exist_ok=True)
    if dist_web.exists():
        shutil.rmtree(dist_web)

    # 1. 确保 Tauri 编译期图标就绪
    ensure_tauri_icon(root)

    print("=== [1/4] Building Headless Python Core (opensight-core) ===")
    pyinstaller_cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onedir", "--windowed",
        "--name=opensight-core",
        "--exclude-module=tkinter",
        "--exclude-module=unittest",
        "--exclude-module=test",
        "--exclude-module=pdb",
        "--exclude-module=pydoc",
        f"--distpath={dist}",
        str(root / "src" / "opensight" / "__main__.py")
    ]
    subprocess.run(pyinstaller_cmd, check=True)

    print("=== [2/4] Building React Web Frontend to dist-web ===")
    subprocess.run(["npm", "run", "build"], cwd=str(root / "web"), shell=True, check=True)
    if not dist_web.is_dir():
        raise RuntimeError(f"Frontend build directory not found: {dist_web}")

    print("=== [3/4] Building Tauri Native Shell ===")
    subprocess.run(["npm", "run", "tauri", "build", "--", "--no-bundle"], cwd=str(root), shell=True, check=True)

    print("=== [4/4] Finalizing Portable Bundle ===")
    tauri_exe = root / "src-tauri" / "target" / "release" / "OpenSight.exe"
    if not tauri_exe.is_file():
        tauri_exe = root / "src-tauri" / "target" / "release" / "opensight.exe"

    if tauri_exe.is_file():
        shutil.copy2(tauri_exe, dist / "OpenSight.exe")
        print(f"[PASS] 成功输出最终原生可执行文件: {dist / 'OpenSight.exe'}")
    else:
        raise RuntimeError(f"未找到 Tauri 编译输出: {tauri_exe}")

    print("\n[SUCCESS] 构建全部完成！最终便携产物位于: dist/OpenSight/OpenSight.exe")
    return 0

if __name__ == "__main__":
    sys.exit(build())
