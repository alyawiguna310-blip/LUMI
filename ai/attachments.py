"""Local image attachments for multimodal prompts.

Images are read-only inputs. Lumi never modifies or deletes the selected file.
The bytes are sent to the configured vision-capable provider when the user
submits the message.
"""
from pathlib import Path
import mimetypes

SUPPORTED_IMAGE_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".heic": "image/heic",
    ".heif": "image/heif",
}
MAX_IMAGE_BYTES = 8 * 1024 * 1024


def validate_image(path: str) -> tuple[bool, str, str]:
    p = Path(path).expanduser()
    if not p.exists():
        return False, "", "image file does not exist"
    if not p.is_file():
        return False, "", "attachment is not a file"

    mime = SUPPORTED_IMAGE_TYPES.get(p.suffix.lower())
    if mime is None:
        guessed, _ = mimetypes.guess_type(str(p))
        if guessed not in SUPPORTED_IMAGE_TYPES.values():
            return False, "", "unsupported image format"

    try:
        size = p.stat().st_size
    except OSError as exc:
        return False, "", f"cannot inspect image: {exc}"

    if size <= 0:
        return False, "", "image is empty"
    if size > MAX_IMAGE_BYTES:
        return False, "", f"image is larger than {MAX_IMAGE_BYTES // (1024 * 1024)} MB"

    return True, mime or mimetypes.guess_type(str(p))[0] or "application/octet-stream", ""
