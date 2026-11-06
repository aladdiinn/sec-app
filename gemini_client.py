import os
import logging
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

PRIMARY_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
FALLBACK_MODEL = os.environ.get("GEMINI_FALLBACK_MODEL", "gemini-2.5-pro")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

_client = None
_client_key = None

def get_gemini_client():
    """
    Returns (client, sdk_type).
    sdk_type will be 'new' if using google-genai, 'old' if using google.generativeai.
    Automatically reloads .env if the key was previously missing or changed.
    """
    global _client, _client_key
    key = os.environ.get("GEMINI_API_KEY") or GEMINI_API_KEY
    if not key:
        load_dotenv(override=True)
        key = os.environ.get("GEMINI_API_KEY")
    if not key:
        _client = None
        _client_key = None
        return None, None
        
    if _client and _client_key == key:
        return _client[0], _client[1]

    try:
        from google import genai
        client = genai.Client(api_key=key, http_options={"api_version": "v1"})
        _client = (client, "new")
        _client_key = key
        return _client
    except ImportError:
        try:
            import google.generativeai as genai
            genai.configure(api_key=key)
            _client = (genai, "old")
            _client_key = key
            return _client
        except ImportError:
            logger.error("Neither 'google-genai' nor 'google-generativeai' is installed.")
            return None, None

def generate_content(prompt: str) -> str:
    """Generate content with automatic fallback across configured and standard models."""
    client, sdk_type = get_gemini_client()
    if not client:
        raise RuntimeError("GEMINI_API_KEY is not configured or SDK is not installed.")

    # Re-read model preferences dynamically if specified in .env
    user_primary = os.environ.get("GEMINI_MODEL") or PRIMARY_MODEL or "gemini-2.5-flash"
    user_fallback = os.environ.get("GEMINI_FALLBACK_MODEL") or FALLBACK_MODEL or "gemini-2.5-pro"

    # Build prioritized candidate list with standard fallbacks
    candidates = [
        user_primary,
        user_fallback,
        "gemini-2.5-flash",
        "gemini-2.0-flash",
        "gemini-1.5-flash",
        "gemini-1.5-pro"
    ]
    seen = set()
    models_to_try = [m for m in candidates if m and not (m in seen or seen.add(m))]
    last_err = None
    
    for model_name in models_to_try:
        try:
            logger.info(f"Sending prompt to Gemini model: {model_name} (SDK: {sdk_type})")
            if sdk_type == "new":
                response = client.models.generate_content(model=model_name, contents=prompt)
                return response.text
            else:
                model = client.GenerativeModel(model_name)
                response = model.generate_content(prompt)
                return response.text
        except Exception as e:
            logger.warning(f"Model {model_name} failed: {e}")
            last_err = e
            
    raise RuntimeError(f"All Gemini models failed. Last error: {last_err}")
