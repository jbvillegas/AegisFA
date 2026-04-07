import os
import mimetypes
import time
from supabase import create_client

_supabase = None

BUCKET_NAME = os.getenv("SUPABASE_BUCKET_NAME", "log-files")
MODEL_BUCKET_NAME = os.getenv("SUPABASE_MODEL_BUCKET_NAME", "ml-models")
UPLOAD_RETRY_ATTEMPTS = int(os.getenv("SUPABASE_UPLOAD_RETRY_ATTEMPTS", "3"))
UPLOAD_RETRY_BASE_DELAY_SECONDS = float(os.getenv("SUPABASE_UPLOAD_RETRY_BASE_DELAY_SECONDS", "0.6"))

def get_client():
    global _supabase 
    if _supabase is None:
        _supabase = create_client(
            os.getenv("SUPABASE_URL"), 
            os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        )
    return _supabase


def _upload_with_retry(upload_callable, attempts=None, base_delay_seconds=None):
    retry_attempts = max(1, int(attempts or UPLOAD_RETRY_ATTEMPTS))
    retry_base_delay = float(base_delay_seconds or UPLOAD_RETRY_BASE_DELAY_SECONDS)
    last_error = None

    for attempt in range(1, retry_attempts + 1):
        try:
            return upload_callable()
        except Exception as exc:
            last_error = exc
            if attempt < retry_attempts:
                time.sleep(min(retry_base_delay * attempt, 3.0))

    raise last_error

def upload_file(file_bytes, filename, org_id):
    client = get_client()
    path = f"{org_id}/{filename}"
    content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    options = {
        "content-type": content_type,
        "upsert": "true",
    }
    _upload_with_retry(lambda: client.storage.from_(BUCKET_NAME).upload(path, file_bytes, options))
    return path

def download_file(storage_path):
    client = get_client()
    return client.storage.from_(BUCKET_NAME).download(storage_path)


def upload_binary(path, file_bytes, bucket_name=None, content_type="application/octet-stream"):
    client = get_client()
    bucket = bucket_name or MODEL_BUCKET_NAME
    options = {
        "content-type": content_type,
        "upsert": "true",
    }
    _upload_with_retry(lambda: client.storage.from_(bucket).upload(path, file_bytes, options))
    return path


def download_binary(path, bucket_name=None):
    client = get_client()
    bucket = bucket_name or MODEL_BUCKET_NAME
    return client.storage.from_(bucket).download(path)