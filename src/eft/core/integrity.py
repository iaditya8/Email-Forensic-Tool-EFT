"""Cryptographic evidence hashing and integrity verification utilities."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, Union


def compute_file_hashes(file_path: Union[str, Path], chunk_size: int = 65536) -> Dict[str, str]:
    """Compute MD5, SHA-1, and SHA-256 hashes of a file in strict read-only mode.

    Args:
        file_path: Absolute or relative path to the target file.
        chunk_size: Size of binary chunks to read in bytes (default 64KB).

    Returns:
        Dictionary containing hexadecimal digests: {"md5": ..., "sha1": ..., "sha256": ...}
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    return {
        "md5": md5_hash.hexdigest(),
        "sha1": sha1_hash.hexdigest(),
        "sha256": sha256_hash.hexdigest(),
    }


def compute_bytes_hashes(data: bytes) -> Dict[str, str]:
    """Compute MD5, SHA-1, and SHA-256 hashes for in-memory byte data.

    Args:
        data: Raw bytes of the payload/attachment.

    Returns:
        Dictionary containing hexadecimal digests: {"md5": ..., "sha1": ..., "sha256": ...}
    """
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
