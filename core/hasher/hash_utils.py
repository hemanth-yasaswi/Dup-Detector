"""
DDAS v2 — Hashing constants for the BLAKE3 pipeline.

This module is the single source of truth for all hashing-related
numeric constants. Importing from here (not from config.settings)
allows the hasher module to remain independent of Qt/UI imports.

Partial hashing strategy:
  For files that pass Stage 1 (size match), we compute a partial hash
  using the first PARTIAL_CHUNK_SIZE bytes + last PARTIAL_CHUNK_SIZE bytes.
  This is effective for large media files where identical files share
  both their header metadata and trailer bytes, while mid-stream corruption
  or edit would still be caught.

  For small files (< 2 × PARTIAL_CHUNK_SIZE), the full file is read —
  effectively collapsing Stage 2 and Stage 3 into one step.
"""

from __future__ import annotations

# ── Chunk sizes ────────────────────────────────────────────────────────────────

PARTIAL_CHUNK_SIZE: int = 128 * 1024
"""
128 KB: Amount of data read from the **head** of a file for the partial hash.
Also used for the **tail** chunk on files exceeding LARGE_FILE_THRESHOLD.
Total partial hash input = up to 256 KB (head + tail).
"""

FULL_HASH_CHUNK_SIZE: int = 64 * 1024
"""
64 KB: Streaming read chunk size during full-file BLAKE3 hashing.
Smaller than PARTIAL_CHUNK_SIZE to keep the read loop responsive and
to allow more frequent progress reporting without excessive syscall overhead.
"""

LARGE_FILE_THRESHOLD: int = 100 * 1024 * 1024
"""
100 MB: Files at or above this size use head + tail partial hashing.
Files below this size use only a head chunk (size < 2 × PARTIAL_CHUNK_SIZE
means the entire file fits in one read anyway).
"""

# ── Algorithm identifier ───────────────────────────────────────────────────────

HASH_ALGO_NAME: str = "blake3"
"""Human-readable algorithm identifier stored in logs and benchmarks."""

# ── Pipeline stage labels (for logging + Developer Mode display) ───────────────

STAGE_LABELS: dict[int, str] = {
    0: "Discovered",
    1: "Partial Hash",
    2: "Full Hash",
}
