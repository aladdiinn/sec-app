#!/usr/bin/env python3
"""
Run this to see which Gemini models your API key can use:
  python check_gemini_models.py
"""
import os
from dotenv import load_dotenv
load_dotenv()

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    print("ERROR: GEMINI_API_KEY not found in .env file")
    exit(1)

from google import genai
client = genai.Client(api_key=GEMINI_API_KEY, http_options={"api_version": "v1"})

print("\n=== Models available for generateContent on your API key ===\n")
for m in client.models.list():
    actions = [a for a in (getattr(m, 'supported_actions', None) or [])]
    # also check supported_generation_methods for older SDK compat
    methods = getattr(m, 'supported_generation_methods', None) or []
    if "generateContent" in methods or "generateContent" in actions or not methods:
        print(f"  {m.name}")
print("\n============================================================\n")
