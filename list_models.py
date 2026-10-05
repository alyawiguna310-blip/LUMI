"""
List the Gemini models your API key can access.
Run: python list_models.py
"""
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the project root
_env_path = Path(__file__).resolve().parent / ".env"
if _env_path.exists():
    load_dotenv(dotenv_path=_env_path)
else:
    load_dotenv()

api_key = os.getenv("GEMINI_API_KEY", "").strip()
if not api_key:
    print("ERROR: GEMINI_API_KEY is not set in .env")
    print(f"Looked for .env at: {_env_path}")
    sys.exit(1)

try:
    from google import genai
except ImportError:
    print("ERROR: google-genai is not installed.")
    print("Run: pip install google-genai")
    sys.exit(1)

print(f"Using API key: {api_key[:8]}...{api_key[-4:]}")
print("Fetching available models...\n")

client = genai.Client(api_key=api_key)

try:
    models = list(client.models.list())
except Exception as e:
    print(f"Failed to list models: {e}")
    sys.exit(1)

if not models:
    print("No models returned. Your key may not have access to any models.")
    sys.exit(1)

print("Models available to your key:\n")
for m in models:
    name = getattr(m, "name", "?")
    short = name.split("/", 1)[-1] if "/" in name else name
    print(f"  {short}")

print("\nCopy one of the names above into GEMINI_MODEL in your .env")
print("Recommended: a model with 'flash' in the name (fast + free tier).")