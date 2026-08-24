import ast
from pathlib import Path

FORBIDDEN_IN_CORE = ("opensight.vpn", "opensight.packaging", "subprocess", "wintun", "tap", "singbox", "routing")
ZERO_NET = (
    "parser.py", "country_resolver.py", "importer.py", "safety.py", "models.py",
    "constants.py", "database.py", "settings.py", "scoring.py", "recommendation.py", "ovpn_security.py"
)

def test_core_never_imports_vpn_or_subprocess():
    core_dir = Path(__file__).resolve().parent.parent / "src" / "opensight" / "core"
    for f in core_dir.glob("*.py"):
        tree = ast.parse(f.read_text(encoding="utf-8-sig"), filename=str(f))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert not any(a.name.lower().startswith(x) for x in FORBIDDEN_IN_CORE), f"边界违规 in {f.name}"
            elif isinstance(node, ast.ImportFrom):
                m = (node.module or "").lower()
                assert not any(m.startswith(x) for x in FORBIDDEN_IN_CORE), f"边界违规 in {f.name}"

def test_zero_network_modules():
    core_dir = Path(__file__).resolve().parent.parent / "src" / "opensight" / "core"
    for name in ZERO_NET:
        f = core_dir / name
        if not f.exists():
            continue
        tree = ast.parse(f.read_text(encoding="utf-8-sig"), filename=str(f))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert a.name not in ("socket", "urllib", "requests", "http"), f"离线模块联网: {name}"
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "") not in ("socket", "urllib", "requests", "http"), f"离线模块联网: {name}"
