"""
File hashing using BLAKE3.
Partial hash = first 128KB + last 128KB (or full file if smaller).
Full hash = entire file in 64KB chunks.
All functions return None on any IO or permission error — never raise.
"""

import time
import blake3
import os
from typing import Optional

from utils.logger import get_logger

PARTIAL_HEAD_BYTES = 128 * 1024   # 128 KB
PARTIAL_TAIL_BYTES = 128 * 1024   # 128 KB
CHUNK_SIZE         = 64  * 1024   # 64 KB read chunks

logger = get_logger(__name__)


def compute_partial_hash(file_path: str) -> Optional[str]:
    """
    Compute BLAKE3 hash of the first 128KB + last 128KB of the file.

    Algorithm:
    1. Open file in binary read mode.
    2. Read up to PARTIAL_HEAD_BYTES from position 0.
    3. If file size > PARTIAL_HEAD_BYTES + PARTIAL_TAIL_BYTES:
         Seek to (file_size - PARTIAL_TAIL_BYTES), read PARTIAL_TAIL_BYTES.
         Feed both chunks into hasher in order: head bytes then tail bytes.
       Else (small file):
         The head bytes already contain the entire file — use those only.
    4. Return hasher.hexdigest().

    Returns None on: FileNotFoundError, PermissionError, OSError, any Exception.
    Logs WARNING with path and error message before returning None.
    Never raises.
    """
    logger.debug("[HASHER] partial_hash started: %s", file_path)
    try:
        hasher = blake3.blake3()
        with open(file_path, "rb") as fh:
            # Step 2: read head
            head = fh.read(PARTIAL_HEAD_BYTES)
            hasher.update(head)

            # Step 3: read tail only if file is large enough
            file_size = os.path.getsize(file_path)
            if file_size > PARTIAL_HEAD_BYTES + PARTIAL_TAIL_BYTES:
                fh.seek(file_size - PARTIAL_TAIL_BYTES)
                tail = fh.read(PARTIAL_TAIL_BYTES)
                hasher.update(tail)

        result = hasher.hexdigest()
        logger.debug("[HASHER] partial_hash done: %s -> %s", file_path, result[:16])
        return result

    except FileNotFoundError as e:
        logger.warning("[HASHER] failed partial_hash: %s — %s", file_path, e)
        return None
    except PermissionError as e:
        logger.warning("[HASHER] failed partial_hash: %s — %s", file_path, e)
        return None
    except OSError as e:
        logger.warning("[HASHER] failed partial_hash: %s — %s", file_path, e)
        return None
    except Exception as e:
        logger.warning("[HASHER] failed partial_hash: %s — %s", file_path, e)
        return None


def compute_full_hash(file_path: str) -> Optional[str]:
    """
    Compute BLAKE3 hash of the entire file using chunked reading.

    Algorithm:
    1. Open file in binary read mode.
    2. Read CHUNK_SIZE bytes at a time in a loop until EOF.
    3. Feed each chunk to hasher.update().
    4. Return hasher.hexdigest().

    Returns None on: FileNotFoundError, PermissionError, OSError, any Exception.
    Logs WARNING with path and error message before returning None.
    Never raises.
    """
    logger.debug("[HASHER] full_hash started: %s", file_path)
    try:
        hasher = blake3.blake3()
        with open(file_path, "rb") as fh:
            while True:
                chunk = fh.read(CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)

        result = hasher.hexdigest()
        logger.debug("[HASHER] full_hash done: %s -> %s", file_path, result[:16])
        return result

    except FileNotFoundError as e:
        logger.warning("[HASHER] failed full_hash: %s — %s", file_path, e)
        return None
    except PermissionError as e:
        logger.warning("[HASHER] failed full_hash: %s — %s", file_path, e)
        return None
    except OSError as e:
        logger.warning("[HASHER] failed full_hash: %s — %s", file_path, e)
        return None
    except Exception as e:
        logger.warning("[HASHER] failed full_hash: %s — %s", file_path, e)
        return None


def is_file_stable(file_path: str, interval: float, retries: int) -> bool:
    """
    Check whether a file has finished being written by polling its size.

    Algorithm:
    1. Get file size at t=0.
    2. Sleep `interval` seconds.
    3. Get file size at t=1.
    4. If sizes are equal: return True (file is stable).
    5. Else: decrement retries. If retries > 0: repeat from step 1.
    6. If retries exhausted: return False.

    Returns False immediately on any OS error (file may have been deleted).
    Uses time.sleep — called from a worker thread, never the main thread.
    """
    attempts = max(1, retries)
    for _ in range(attempts):
        try:
            size_before = os.path.getsize(file_path)
        except OSError:
            return False

        time.sleep(interval)

        try:
            size_after = os.path.getsize(file_path)
        except OSError:
            return False

        if size_before == size_after:
            return True

    return False
