from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Tuple


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ensure_base_dir(base: Path) -> None:
    base.mkdir(parents=True, exist_ok=True)


def safe_join(base: Path, *parts: str) -> Path:
    """Join path parts under base ensuring the result stays within base (zip-slip guard)."""
    candidate = (base / Path(*parts)).resolve()
    base_resolved = base.resolve()
    if not str(candidate).startswith(str(base_resolved)):
        raise ValueError("unsafe path traversal detected")
    return candidate


def save_bytes(base: Path, rel_name: str, data: bytes) -> Tuple[Path, str, int]:
    """Save bytes under base safely. Returns (path, sha256, size)."""
    ensure_base_dir(base)
    target = safe_join(base, rel_name)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "wb") as f:
        f.write(data)
    os.chmod(target, 0o600)
    digest = sha256_bytes(data)
    size = len(data)
    return target, digest, size

