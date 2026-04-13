"""
PreviewService — generates file preview data for side-by-side comparison.

Supported types:
  Images : .jpg .jpeg .png .gif .bmp .webp → base64-encoded thumbnail
  Text   : .txt .md .json .log .csv .py .js .html .xml → first N lines
  Other  : metadata only (size, dates, hash)

Never loads full file into memory for large files.
All methods return a dict — never raise exceptions to caller.
Called from the main thread (dialog opened it) but operations are fast
because previews are capped at small sizes.
"""

import os
import base64
import difflib
from pathlib import Path
from datetime import datetime
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)

TEXT_EXTENSIONS = {
    ".txt", ".md", ".json", ".log", ".csv", ".py",
    ".js", ".ts", ".html", ".xml", ".yaml", ".yml",
    ".ini", ".cfg", ".toml", ".rst",
}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"}

PREVIEW_MAX_TEXT_LINES  = 200
PREVIEW_MAX_IMAGE_BYTES = 200 * 1024   # 200KB — thumbnail if larger
THUMBNAIL_SIZE          = (300, 300)


class PreviewService:

    def get_preview(self, file_path: str) -> dict:
        """
        Generate preview data for a single file.

        Returns dict with keys:
          path           : str
          exists         : bool
          size_bytes     : int
          size_human     : str
          modified_at    : str (human-readable datetime)
          preview_type   : "image" | "text" | "metadata_only"
          content        : str | None (base64 for image, text for text)
          error          : str | None
        """
        result = {
            "path":        file_path,
            "exists":      False,
            "size_bytes":  0,
            "size_human":  "unknown",
            "modified_at": "unknown",
            "preview_type": "metadata_only",
            "content":     None,
            "error":       None,
        }

        try:
            if not os.path.isfile(file_path):
                result["error"] = "File not found"
                return result

            stat = os.stat(file_path)
            result["exists"]      = True
            result["size_bytes"]  = stat.st_size
            result["size_human"]  = self._format_size(stat.st_size)
            result["modified_at"] = datetime.fromtimestamp(stat.st_mtime).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            ext = Path(file_path).suffix.lower()

            if ext in IMAGE_EXTENSIONS:
                result["preview_type"] = "image"
                result["content"]      = self._get_image_preview(file_path, stat.st_size)
            elif ext in TEXT_EXTENSIONS:
                result["preview_type"] = "text"
                result["content"]      = self._get_text_preview(file_path)

        except Exception as e:
            result["error"] = str(e)
            logger.warning("[PREVIEW] error previewing %s: %s", file_path, e)

        return result

    def compare(self, path_a: str, path_b: str) -> dict:
        """
        Generate side-by-side comparison data for two files.

        Returns dict with keys:
          file_a        : dict (from get_preview)
          file_b        : dict (from get_preview)
          diff_lines    : list[str] | None (unified diff for text files)
          same_content  : bool | None
          error         : str | None
        """
        result = {
            "file_a":      self.get_preview(path_a),
            "file_b":      self.get_preview(path_b),
            "diff_lines":  None,
            "same_content": None,
            "error":       None,
        }

        try:
            ext_a = Path(path_a).suffix.lower()
            ext_b = Path(path_b).suffix.lower()

            # Only diff if both are text
            if ext_a in TEXT_EXTENSIONS and ext_b in TEXT_EXTENSIONS:
                lines_a = self._read_text_lines(path_a)
                lines_b = self._read_text_lines(path_b)
                diff = list(difflib.unified_diff(
                    lines_a, lines_b,
                    fromfile=os.path.basename(path_a),
                    tofile=os.path.basename(path_b),
                    lineterm="",
                ))
                result["diff_lines"]  = diff[:100]  # cap at 100 lines
                result["same_content"] = len(diff) == 0

        except Exception as e:
            result["error"] = str(e)
            logger.warning("[PREVIEW] compare error: %s", e)

        return result

    def _get_image_preview(self, file_path: str, file_size: int) -> str | None:
        """
        Return base64-encoded image.
        If size > PREVIEW_MAX_IMAGE_BYTES: generate thumbnail via Pillow.
        Returns None if Pillow not available or on error.
        """
        try:
            from PIL import Image
            import io

            if file_size <= PREVIEW_MAX_IMAGE_BYTES:
                with open(file_path, "rb") as f:
                    return base64.b64encode(f.read()).decode("utf-8")
            else:
                with Image.open(file_path) as img:
                    img.thumbnail(THUMBNAIL_SIZE)
                    buf = io.BytesIO()
                    fmt = img.format or "JPEG"
                    img.save(buf, format=fmt)
                    return base64.b64encode(buf.getvalue()).decode("utf-8")

        except ImportError:
            logger.warning("[PREVIEW] Pillow not available — image preview disabled")
            return None
        except Exception as e:
            logger.warning("[PREVIEW] image preview failed for %s: %s", file_path, e)
            return None

    def _get_text_preview(self, file_path: str) -> str | None:
        """Read first PREVIEW_MAX_TEXT_LINES lines of a text file."""
        try:
            lines = self._read_text_lines(file_path)
            return "\n".join(lines)
        except Exception as e:
            logger.warning("[PREVIEW] text preview failed for %s: %s", file_path, e)
            return None

    def _read_text_lines(self, file_path: str) -> list[str]:
        """Read up to PREVIEW_MAX_TEXT_LINES lines, trying UTF-8 then latin-1."""
        for encoding in ("utf-8", "latin-1"):
            try:
                with open(file_path, "r", encoding=encoding, errors="replace") as f:
                    return [line.rstrip("\n") for _, line in
                            zip(range(PREVIEW_MAX_TEXT_LINES), f)]
            except Exception:
                continue
        return []

    @staticmethod
    def _format_size(size: int) -> str:
        if size >= 1024 ** 3:
            return f"{size / (1024 ** 3):.1f} GB"
        if size >= 1024 ** 2:
            return f"{size / (1024 ** 2):.1f} MB"
        if size >= 1024:
            return f"{size / 1024:.1f} KB"
        return f"{size} B"


# Module-level singleton
preview_service = PreviewService()
