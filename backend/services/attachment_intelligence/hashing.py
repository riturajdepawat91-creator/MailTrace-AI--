"""
Attachment Intelligence Engine - Cryptographic Hashing

Streaming, memory-safe cryptographic hashing utilities for
email attachments and suspicious files.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO, Dict, Iterable, Optional, Union

from .models import FileHashes


DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MB


SUPPORTED_ALGORITHMS = (
    "md5",
    "sha1",
    "sha256",
    "sha512",
)


def _create_hashers(
    algorithms: Iterable[str],
) -> Dict[str, "hashlib._Hash"]:
    """
    Create hashlib objects for the requested algorithms.
    """

    hashers = {}

    for algorithm in algorithms:
        algorithm = algorithm.lower().strip()

        if algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Unsupported hashing algorithm: {algorithm}"
            )

        hashers[algorithm] = hashlib.new(algorithm)

    return hashers


def calculate_hashes_from_stream(
    stream: BinaryIO,
    algorithms: Iterable[str] = SUPPORTED_ALGORITHMS,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Dict[str, str]:
    """
    Calculate hashes from an open binary stream.

    The file is processed in chunks, making this safe for
    large attachments without loading the entire file into memory.
    """

    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    hashers = _create_hashers(algorithms)

    while True:
        chunk = stream.read(chunk_size)

        if not chunk:
            break

        for hasher in hashers.values():
            hasher.update(chunk)

    return {
        algorithm: hasher.hexdigest()
        for algorithm, hasher in hashers.items()
    }


def calculate_hashes_from_bytes(
    data: bytes,
    algorithms: Iterable[str] = SUPPORTED_ALGORITHMS,
) -> Dict[str, str]:
    """
    Calculate hashes directly from bytes.
    """

    hashers = _create_hashers(algorithms)

    for hasher in hashers.values():
        hasher.update(data)

    return {
        algorithm: hasher.hexdigest()
        for algorithm, hasher in hashers.items()
    }


def calculate_file_hashes(
    file_path: Union[str, Path],
    algorithms: Iterable[str] = SUPPORTED_ALGORITHMS,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Dict[str, str]:
    """
    Calculate cryptographic hashes for a file on disk.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    with path.open("rb") as stream:
        return calculate_hashes_from_stream(
            stream=stream,
            algorithms=algorithms,
            chunk_size=chunk_size,
        )


def calculate_standard_file_hashes(
    file_path: Union[str, Path],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> FileHashes:
    """
    Calculate standard hashes used for threat intelligence
    and malware identification.
    """

    results = calculate_file_hashes(
        file_path=file_path,
        algorithms=("md5", "sha1", "sha256"),
        chunk_size=chunk_size,
    )

    return FileHashes(
        md5=results.get("md5"),
        sha1=results.get("sha1"),
        sha256=results.get("sha256"),
    )


def get_file_size(
    file_path: Union[str, Path],
) -> int:
    """
    Return the size of a file in bytes.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    return path.stat().st_size


def validate_hash(
    value: Optional[str],
    algorithm: str,
) -> bool:
    """
    Validate whether a hash string matches the expected
    length and hexadecimal format for an algorithm.
    """

    if not value or not isinstance(value, str):
        return False

    algorithm = algorithm.lower().strip()

    expected_lengths = {
        "md5": 32,
        "sha1": 40,
        "sha256": 64,
        "sha512": 128,
    }

    expected_length = expected_lengths.get(algorithm)

    if expected_length is None:
        raise ValueError(
            f"Unsupported hashing algorithm: {algorithm}"
        )

    normalized = value.strip().lower()

    if len(normalized) != expected_length:
        return False

    try:
        int(normalized, 16)
        return True

    except ValueError:
        return False


def normalize_hash(
    value: str,
) -> str:
    """
    Normalize a hash value for reliable comparison.
    """

    if not isinstance(value, str):
        raise TypeError("Hash value must be a string")

    return value.strip().lower()


def hashes_match(
    hash_a: str,
    hash_b: str,
) -> bool:
    """
    Compare two hashes safely after normalization.
    """

    return normalize_hash(hash_a) == normalize_hash(hash_b)


__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "SUPPORTED_ALGORITHMS",
    "calculate_hashes_from_stream",
    "calculate_hashes_from_bytes",
    "calculate_file_hashes",
    "calculate_standard_file_hashes",
    "get_file_size",
    "validate_hash",
    "normalize_hash",
    "hashes_match",
]
