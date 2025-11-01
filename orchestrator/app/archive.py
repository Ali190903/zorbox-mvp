from __future__ import annotations

import io
import zipfile
from typing import List, Optional, Tuple


class ArchiveInfo(Tuple[str, bool, int]):
    # (type, is_encrypted, members_count)
    pass


def detect_zip_encryption(data: bytes) -> Optional[ArchiveInfo]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            members = zf.infolist()
            enc = any(i.flag_bits & 0x1 for i in members) if members else False
            return ArchiveInfo(("zip", enc, len(members)))
    except zipfile.BadZipFile:
        return None


def detect_archive(file_name: Optional[str], data: bytes) -> Optional[ArchiveInfo]:
    # MVP: only ZIP detection via stdlib
    info = detect_zip_encryption(data)
    if info:
        return info
    return None

