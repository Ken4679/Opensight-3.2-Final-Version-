import json
import re
import sys
from pathlib import Path
from opensight.core.constants import APP_VERSION

CANONICAL_VERSION = "3.2.0"

def test_canonical_version_constants():
    assert APP_VERSION == CANONICAL_VERSION, f"constants.py version {APP_VERSION} != {CANONICAL_VERSION}"

def test_python_package_init_version():
    import opensight
    assert opensight.__version__ == CANONICAL_VERSION, f"opensight.__version__ {opensight.__version__} != {CANONICAL_VERSION}"

def test_package_json_versions():
    root = Path(__file__).resolve().parent.parent
    
    # Root package.json
    root_pkg = json.loads((root / "package.json").read_text(encoding="utf-8"))
    assert root_pkg["version"] == CANONICAL_VERSION, f"Root package.json version {root_pkg['version']} != {CANONICAL_VERSION}"

    # Web package.json
    web_pkg = json.loads((root / "web" / "package.json").read_text(encoding="utf-8"))
    assert web_pkg["version"] == CANONICAL_VERSION, f"Web package.json version {web_pkg['version']} != {CANONICAL_VERSION}"

def test_pyproject_version():
    root = Path(__file__).resolve().parent.parent
    pyproject_text = (root / "pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{CANONICAL_VERSION}"' in pyproject_text, "pyproject.toml version mismatch"

def test_tauri_versions():
    root = Path(__file__).resolve().parent.parent
    
    # tauri.conf.json
    tauri_conf = json.loads((root / "src-tauri" / "tauri.conf.json").read_text(encoding="utf-8"))
    assert tauri_conf["version"] == CANONICAL_VERSION, f"tauri.conf.json version {tauri_conf['version']} != {CANONICAL_VERSION}"

    # Cargo.toml
    cargo_text = (root / "src-tauri" / "Cargo.toml").read_text(encoding="utf-8")
    assert f'version = "{CANONICAL_VERSION}"' in cargo_text, "Cargo.toml version mismatch"
