from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


def capture_jpeg(
    device: str,
    *,
    prefer_ffmpeg: bool = True,
    width: int | None = None,
    height: int | None = None,
) -> bytes | None:
    """
    Capture one frame from a V4L2 device (e.g. /dev/video0).
    Tries ffmpeg first if prefer_ffmpeg and binary exists, else OpenCV.
    """
    if prefer_ffmpeg and shutil.which("ffmpeg"):
        return _capture_ffmpeg(device, width=width, height=height)
    return _capture_opencv(device, width=width, height=height)


def _capture_ffmpeg(
    device: str,
    *,
    width: int | None,
    height: int | None,
) -> bytes | None:
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
        out_path = tmp.name

    try:
        cmd = [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-f",
            "v4l2",
        ]
        if width and height:
            cmd.extend(["-video_size", f"{width}x{height}"])
        cmd.extend(["-i", device, "-frames:v", "1", "-q:v", "4", out_path])
        r = subprocess.run(cmd, capture_output=True, timeout=15, check=False)
        if r.returncode != 0:
            logger.warning("ffmpeg capture failed: %s", (r.stderr or b"").decode(errors="replace")[:400])
            return None
        data = Path(out_path).read_bytes()
        return data if data else None
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning("ffmpeg capture error: %s", e)
        return None
    finally:
        try:
            Path(out_path).unlink(missing_ok=True)
        except OSError:
            pass


def _capture_opencv(
    device: str,
    *,
    width: int | None,
    height: int | None,
) -> bytes | None:
    try:
        import cv2  # type: ignore[import-untyped]
    except ImportError:
        logger.warning("OpenCV not installed and ffmpeg failed — cannot capture")
        return None

    try:
        cap = cv2.VideoCapture(device, cv2.CAP_V4L2)
        if not cap.isOpened():
            cap = cv2.VideoCapture(device)
        if not cap.isOpened():
            logger.warning("OpenCV could not open camera: %s", device)
            return None
        if width and height:
            cap.set(cv2.CAP_PROP_FRAME_WIDTH, width)
            cap.set(cv2.CAP_PROP_FRAME_HEIGHT, height)
        ok, frame = cap.read()
        cap.release()
        if not ok or frame is None:
            return None
        ok2, buf = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 85])
        if not ok2:
            return None
        return buf.tobytes()
    except cv2.error as e:  # type: ignore[attr-defined]
        logger.warning("OpenCV capture error: %s", e)
        return None
