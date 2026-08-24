import math
import os
import struct
import zlib
from pathlib import Path

def create_opensight_png(size: int) -> bytes:
    """
    Generates a high-quality RGBA PNG image with the OpenSight Shield & Eye design.
    """
    width = size
    height = size
    pixels = bytearray(width * height * 4)

    # Center and scale
    cx = width / 2.0
    cy = height / 2.0
    s = size / 32.0

    # Draw shield and eye geometry
    for y in range(height):
        for x in range(width):
            idx = (y * width + x) * 4
            nx = (x - cx) / (s * 12.0)
            ny = (y - cy) / (s * 12.0)

            # Shield shape calculation:
            # Top edge: y between -1.0 and -0.6
            # Sides: x between -0.8 and 0.8
            # Bottom curve: tapering to point (0, 1.1)
            in_shield = False
            border_shield = False

            # Shield boundary math
            if -1.0 <= ny <= 1.1:
                if ny <= -0.4:
                    # Top section with slight chevron curve
                    top_y = -0.9 + 0.15 * (nx ** 2)
                    max_x = 0.85
                    if ny >= top_y and abs(nx) <= max_x:
                        in_shield = True
                        if abs(abs(nx) - max_x) < 0.12 or abs(ny - top_y) < 0.12:
                            border_shield = True
                else:
                    # Curved tapering down
                    curve_x = 0.85 * (1.0 - ((ny + 0.4) / 1.5) ** 1.8)
                    if curve_x > 0 and abs(nx) <= curve_x:
                        in_shield = True
                        if abs(abs(nx) - curve_x) < 0.12 or ny > 1.0:
                            border_shield = True

            # Center target circle / pupil
            dist_center = math.sqrt(nx ** 2 + (ny + 0.05) ** 2)
            in_ring = 0.28 <= dist_center <= 0.48
            in_dot = dist_center <= 0.18

            if in_shield:
                if in_dot:
                    # White core
                    pixels[idx] = 255      # R
                    pixels[idx + 1] = 255  # G
                    pixels[idx + 2] = 255  # B
                    pixels[idx + 3] = 255  # A
                elif in_ring:
                    # Bright Cyan/White Ring
                    pixels[idx] = 191      # R
                    pixels[idx + 1] = 219  # G
                    pixels[idx + 2] = 254  # B (blue-200)
                    pixels[idx + 3] = 255  # A
                elif border_shield:
                    # Bright Shield Outline
                    pixels[idx] = 96       # R
                    pixels[idx + 1] = 165  # G
                    pixels[idx + 2] = 250  # B (blue-400)
                    pixels[idx + 3] = 255  # A
                else:
                    # Shield Gradient Fill (Blue-600 #2563eb to Blue-800 #1e40af)
                    grad = (ny + 1.0) / 2.1
                    r = int(37 * (1 - grad) + 30 * grad)
                    g = int(99 * (1 - grad) + 64 * grad)
                    b = int(235 * (1 - grad) + 175 * grad)
                    pixels[idx] = r
                    pixels[idx + 1] = g
                    pixels[idx + 2] = b
                    pixels[idx + 3] = 250
            else:
                # Transparent outside
                pixels[idx] = 0
                pixels[idx + 1] = 0
                pixels[idx + 2] = 0
                pixels[idx + 3] = 0

    # Encode to PNG
    raw_rows = []
    for y in range(height):
        row = bytearray([0])  # Filter type 0 (None)
        start = y * width * 4
        row.extend(pixels[start : start + width * 4])
        raw_rows.append(bytes(row))

    compressed = zlib.compress(b"".join(raw_rows), level=9)
    png = bytearray(b"\x89PNG\r\n\x1a\n")
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    png.extend(struct.pack(">I", len(ihdr)) + b"IHDR" + ihdr + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr) & 0xFFFFFFFF))
    png.extend(struct.pack(">I", len(compressed)) + b"IDAT" + compressed + struct.pack(">I", zlib.crc32(b"IDAT" + compressed) & 0xFFFFFFFF))
    png.extend(struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF))
    return bytes(png)

def create_multi_ico(sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]) -> bytes:
    png_entries = []
    for w, h in sizes:
        png_data = create_opensight_png(w)
        png_entries.append((w, h, png_data))

    header = struct.pack("<HHH", 0, 1, len(png_entries))
    offset = 6 + len(png_entries) * 16
    dir_entries = []
    data_blobs = []

    for w, h, data in png_entries:
        bw = w if w < 256 else 0
        bh = h if h < 256 else 0
        dir_entries.append(struct.pack("<BBBBHHII", bw, bh, 0, 0, 1, 32, len(data), offset))
        offset += len(data)
        data_blobs.append(data)

    return header + b"".join(dir_entries) + b"".join(data_blobs)

def generate_all_icons(root: Path):
    icons_dir = root / "src-tauri" / "icons"
    icons_dir.mkdir(parents=True, exist_ok=True)

    # 1. Tauri required pngs
    (icons_dir / "32x32.png").write_bytes(create_opensight_png(32))
    (icons_dir / "128x128.png").write_bytes(create_opensight_png(128))
    (icons_dir / "128x128@2x.png").write_bytes(create_opensight_png(256))
    (icons_dir / "icon.png").write_bytes(create_opensight_png(512))

    # Windows store & uwp icons for tauri
    for name, s in [
        ("Square30x30Logo.png", 30),
        ("Square44x44Logo.png", 44),
        ("Square71x71Logo.png", 71),
        ("Square89x89Logo.png", 89),
        ("Square107x107Logo.png", 107),
        ("Square142x142Logo.png", 142),
        ("Square150x150Logo.png", 150),
        ("Square284x284Logo.png", 284),
        ("Square310x310Logo.png", 310),
        ("StoreLogo.png", 50),
    ]:
        (icons_dir / name).write_bytes(create_opensight_png(s))

    # 2. Multi-resolution ICO
    ico_bytes = create_multi_ico()
    (icons_dir / "icon.ico").write_bytes(ico_bytes)
    (root / "opensight.ico").write_bytes(ico_bytes)

    # Dummy icns for non-mac builds if needed
    (icons_dir / "icon.icns").write_bytes(create_opensight_png(512))

    # 3. Web public assets
    web_public = root / "web" / "public"
    web_public.mkdir(parents=True, exist_ok=True)
    (web_public / "favicon.ico").write_bytes(ico_bytes)
    (web_public / "icon.png").write_bytes(create_opensight_png(128))

    print(f"[SUCCESS] 生成所有图标至 {icons_dir} 和 {web_public}")

if __name__ == "__main__":
    generate_all_icons(Path(__file__).resolve().parent.parent)
