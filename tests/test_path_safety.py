from pathlib import Path
import pytest
from opensight.core.safety import validate_subpath, SecurityViolationError

def test_path_safety_traversal(tmp_path: Path):
    with pytest.raises(SecurityViolationError):
        validate_subpath(tmp_path, tmp_path.parent / "escape.txt")