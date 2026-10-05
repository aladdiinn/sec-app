import os
import logging
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

PRIMARY_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
FALLBACK_MODEL = os.environ.get("GEMINI_FALLBACK_MODEL", "gemini-2.5-pro")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

_client = None

def get_gemini_client():
    """
    Returns (client, sdk_type).
    sdk_type will be 'new' if using google-genai, 'old' if using google.generativeai.
    """
    global _client
    if not GEMINI_API_KEY:
        return None, None
        
    if _client:
        return _client[0], _client[1]

    try:
        from google import genai
        client = genai.Client(api_key=GEMINI_API_KEY, http_options={"api_version": "v1"})
        _client = (client, "new")
        return _client
    except ImportError:
        try:
            import google.generativeai as genai
            genai.configure(api_key=GEMINI_API_KEY)
            _client = (genai, "old")
            return _client
        except ImportError:
            logger.error("Neither 'google-genai' nor 'google-generativeai' is installed.")
            return None, None

def generate_content(prompt: str) -> str:
    """Generate content with automatic fallback."""
    client, sdk_type = get_gemini_client()
    if not client:
        raise RuntimeError("GEMINI_API_KEY is not configured or SDK is not installed.")

    models_to_try = [PRIMARY_MODEL, FALLBACK_MODEL]
    last_err = None
    
    for model_name in models_to_try:
        if not model_name:
            continue
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
            
    raise RuntimeError(f"All models failed. Last error: {last_err}")
