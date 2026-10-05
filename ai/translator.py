"""
Normalizes any user input to clean English before it reaches the LLM.

- Indonesian input â†’ translated to English
- English (possibly with accent-related typos) â†’ corrected to natural English
- Mixed code-switch â†’ normalized to English
"""
import logging

from google import genai
from google.genai import types

logger = logging.getLogger(__name__)

_TRANSLATE_PROMPT = """You normalize user messages for an English-only AI assistant.

You receive one message from a user. It may be in:
- Indonesian (formal or casual/slang)
- English (possibly with Indonesian accent that caused transcription errors)
- A mix of Indonesian and English

Your job:
1. Understand what the user actually means, using context if needed.
2. Output ONE clean, natural English sentence (or short paragraph) that means the same thing.
3. If the input is already clean English, output it unchanged (or with only obvious typo fixes).
4. If the input contains nonsense words that look like mishears (e.g. "Yolong" â†’ "tolong", "kota nya saya" â†’ "kok tanya saya"), infer the most likely intended meaning.
5. NEVER answer the question. NEVER add commentary. NEVER explain yourself.
6. Output ONLY the normalized English text â€” nothing else.

Examples:
Input: "Halo Lumi, apa kabar?"
Output: Hello Lumi, how are you?

Input: "yo ndak tahu kok tanya saya"
Output: I don't know, why are you asking me?

Input: "1 + 1 berapa?"
Output: What is 1 + 1?

Input: "aku juga ga tau"
Output: I also don't know.

Input: "hey can you help me with my school project"
Output: Hey, can you help me with my school project?

Input: "Yolong dah tau, kota nya saya"
Output: I don't know, why are you asking me?

Input: "Sekarang serius sekarang"
Output: I'm serious now.
"""


class Translator:
    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model
        self._client = None

    def _ensure_client(self):
        if self._client is not None:
            return
        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY missing â€” translator disabled.")
        self._client = genai.Client(api_key=self.api_key)

    def normalize(self, text: str) -> str:
        """
        Return an English version of the user's message.
        Falls back to the original text on failure.
        """
        text = (text or "").strip()
        if not text:
            return ""

        # Quick heuristic: if it's short and contains only ASCII letters,
        # it's probably already English â€” skip the translation call.
        if _looks_like_english(text):
            return text

        try:
            self._ensure_client()
        except Exception:
            logger.exception("Translator client init failed")
            return text

        try:
            response = self._client.models.generate_content(
                model=self.model,
                contents=text,
                config=types.GenerateContentConfig(
                    system_instruction=_TRANSLATE_PROMPT,
                    temperature=0.0,
                    max_output_tokens=200,
                ),
            )
            out = (getattr(response, "text", "") or "").strip()
            # Strip surrounding quotes if the model added them
            if out.startswith('"') and out.endswith('"'):
                out = out[1:-1].strip()
            if out:
                logger.info("Translated: %r â†’ %r", text, out)
                return out
            return text
        except Exception:
            logger.exception("Translation failed; passing original text")
            return text


def _looks_like_english(text: str) -> bool:
    """
    Very rough check: does this look like English?
    Detects common Indonesian-only words and rejects those.
    """
    low = " " + text.lower() + " "

    # Indonesian-only common words / particles
    id_markers = [
        " yang ", " dan ", " aku ", " kamu ", " gak ", " nggak ",
        " ndak ", " kok ", " saya ", " kita ", " kami ", " mereka ",
        " apa ", " kenapa ", " gimana ", " bagaimana ", " bisa ",
        " enggak ", " bukan ", " juga ", " banget ", " udah ",
        " sudah ", " belum ", " berapa ", " tolong ", " halo ",
        " apa kabar", " ngapain ", " lagi ", " mau ", " ingin ",
    ]
    for marker in id_markers:
        if marker in low:
            return False

    # If it contains non-ASCII letters, likely not English
    for ch in text:
        if ord(ch) > 127 and ch.isalpha():
            return False

    return True
