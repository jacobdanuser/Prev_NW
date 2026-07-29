#!/usr/bin/env python3
"""Metadata helpers for authorized local evidence."""

from __future__ import annotations

import hashlib
from pathlib import Path


def file_metadata(path: str | Path) -> dict:
    p = Path(path)
    stat = p.stat()
    digest = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "path": str(p),
        "name": p.name,
        "suffix": p.suffix,
        "size_bytes": stat.st_size,
        "modified_ns": stat.st_mtime_ns,
        "sha256": digest.hexdigest(),
    }
