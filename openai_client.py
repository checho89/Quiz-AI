import os
from openai import OpenAI
from dotenv import load_dotenv

_client = None

def get_client() -> OpenAI:
    """Create a singleton OpenAI client. Ensures .env is loaded."""
    global _client
    if _client is None:
        load_dotenv()
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is not set")
        _client = OpenAI(api_key=api_key)
    return _client
