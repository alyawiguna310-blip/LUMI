"""Read-only image understanding for user attachments."""
from google import genai
from google.genai import types

from ai.attachments import validate_image
from config import config

def analyze_image(path: str, prompt: str) -> str:
    ok, mime, error = validate_image(path)
    if not ok:
        raise RuntimeError(f"image attachment rejected: {error}")
    if not config.GEMINI_API_KEY:
        raise RuntimeError("Gemini vision is unavailable because GEMINI_API_KEY is not configured.")
    with open(path, "rb") as image_file:
        image_bytes = image_file.read()
    client = genai.Client(api_key=config.GEMINI_API_KEY)
    response = client.models.generate_content(
        model=config.GEMINI_MODEL,
        contents=[
            types.Part.from_bytes(data=image_bytes, mime_type=mime),
            prompt,
        ],
    )
    text = (response.text or "").strip()
    if not text:
        raise RuntimeError("Gemini vision returned an empty response.")
    return text
