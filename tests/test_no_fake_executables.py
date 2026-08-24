from pathlib import Path

def test_source_contains_no_stub_or_fake_binary_logic():
    forbidden_tokens = [
        "".join(["MZ_", "OPENSIGHT_", "PORTABLE_", "EXECUTABLE_", "STUB"]),
        "".join(["FAKE_", "BINARY"]),
        "".join(["MOCK_", "EXECUTABLE"]),
        "".join(["STUB_", "EXE"]),
    ]

    root = Path(__file__).resolve().parent.parent
    src_dir = root / "src"
    scripts_dir = root / "scripts"

    for search_dir in (src_dir, scripts_dir):
        for py_file in search_dir.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            for token in forbidden_tokens:
                assert token not in content, f"源码中检测到违规的伪造二进制字符串 '{token}' in {py_file}"