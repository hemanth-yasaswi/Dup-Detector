"""
DDAS v2 — BLAKE3 hasher implementation.

This module provides the BLAKE3 hashing functions used in all three
pipeline stages. BLAKE3 is the single canonical algorithm for the
production deduplication pipeline.

Benchmarking of BLAKE3 (throughput/CPU/memory) is available in the
separate benchmarks/ module and does NOT involve any other algorithm.

Pipeline integration:
  Stage 2 (partial):  compute_partial_hash(path)
  Stage 3 (full):     compute_full_hash(path)

Thread safety:
  Both functions create a fresh blake3.hasher() per call, making them
  safe to call concurrently from multiple ThreadPoolExecutor workers.
"""

from __future__ import annotations

import logging
from pathlib import Path

from core.hasher.hash_utils import (
    PARTIAL_CHUNK_SIZE,
    FULL_HASH_CHUNK_SIZE,
    LARGE_FILE_THRESHOLD,
)

log = logging.getLogger(__name__)

# blake3 is imported lazily so that the module can be imported without the
# library installed — helpful for Phase 1/2 test environments.
try:
    import blake3 as _blake3
    BLAKE3_AVAILABLE = True
except ImportError:
    BLAKE3_AVAILABLE = False
    log.warning(
        "blake3 library not installed. "
        "Install with: pip install blake3  "
        "Hashing operations will raise RuntimeError until it is available."
    )


def _require_blake3() -> None:
    if not BLAKE3_AVAILABLE:
        raise RuntimeError(
            "blake3 library is required for hashing. "
            "Install with: pip install blake3"
        )


def compute_partial_hash(path: str | Path) -> str:
    """
    Compute the BLAKE3 partial hash for Stage 2 duplicate detection.

    Strategy:
      - Files < 2 × PARTIAL_CHUNK_SIZE  → hash the entire file
      - Files ≥ LARGE_FILE_THRESHOLD    → hash first chunk + last chunk
      - All others                      → hash first chunk only

    This approach ensures that:
      1. Small files get a complete hash (no false-positive risk).
      2. Large media files (video, audio, images) are efficiently profiled
         using their header and trailer — the most discriminating regions.

    Args:
        path: Absolute path to the file to hash.

    Returns:
        Hex string of the BLAKE3 digest.

    Raises:
        RuntimeError:    blake3 library not installed.
        FileNotFoundError: path does not exist.
        OSError:         file cannot be read.
    """
    _require_blake3()
    p = Path(path)
    file_size = p.stat().st_size
    hasher = _blake3.blake3()

    with p.open("rb") as fh:
        if file_size < 2 * PARTIAL_CHUNK_SIZE:
            # Small file: read entirely
            hasher.update(fh.read())
        elif file_size >= LARGE_FILE_THRESHOLD:
            # Large file: head + tail
            hasher.update(fh.read(PARTIAL_CHUNK_SIZE))
            fh.seek(-PARTIAL_CHUNK_SIZE, 2)          # seek from end
            hasher.update(fh.read(PARTIAL_CHUNK_SIZE))
        else:
            # Medium file: head only
            hasher.update(fh.read(PARTIAL_CHUNK_SIZE))

    return hasher.hexdigest()


def compute_full_hash(path: str | Path) -> str:
    """
    Compute the full BLAKE3 hash of a file for Stage 3 confirmation.

    Reads the file in FULL_HASH_CHUNK_SIZE chunks to support
    arbitrarily large files without loading them into memory.

    Args:
        path: Absolute path to the file to hash.

    Returns:
        Hex string of the BLAKE3 digest.

    Raises:
        RuntimeError:    blake3 library not installed.
        FileNotFoundError: path does not exist.
        OSError:         file cannot be read.
    """
    _require_blake3()
    hasher = _blake3.blake3()

    with Path(path).open("rb") as fh:
        while chunk := fh.read(FULL_HASH_CHUNK_SIZE):
            hasher.update(chunk)

    return hasher.hexdigest()
