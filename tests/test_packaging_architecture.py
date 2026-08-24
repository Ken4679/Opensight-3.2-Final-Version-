import ast
from pathlib import Path

def test_core_never_imports_packaging():
    core_dir = Path(__file__).resolve().parent.parent / "src" / "opensight" / "core"
    for f in core_dir.glob("*.py"):
        tree = ast.parse(f.read_text(encoding="utf-8-sig"), filename=str(f))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert not a.name.startswith("opensight.packaging")
            elif isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("opensight.packaging")
