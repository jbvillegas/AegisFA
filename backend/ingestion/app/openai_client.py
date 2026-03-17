import os
from openai import OpenAI

_client = None


def get_openai_client() -> OpenAI:
    global _client
    if _client is None:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY must be set in environment variables.")
        _client = OpenAI(api_key=api_key)
    return _client


def get_embedding(text: str, model: str = "text-embedding-3-small") -> list[float]:
    client = get_openai_client()
    response = client.embeddings.create(input=text, model=model)
    return response.data[0].embedding
