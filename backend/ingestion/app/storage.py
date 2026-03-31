import os
from supabase import create_client

_supabase = None

BUCKET_NAME = os.getenv("SUPABASE_BUCKET_NAME", "log-files")
MODEL_BUCKET_NAME = os.getenv("SUPABASE_MODEL_BUCKET_NAME", "ml-models")

def get_client():
    global _supabase 
    if _supabase is None:
        _supabase = create_client(
            os.getenv("SUPABASE_URL"), 
            os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        )
    return _supabase

def upload_file(file_bytes, filename, org_id):
    client = get_client()
    path = f"{org_id}/{filename}"
    client.storage.from_(BUCKET_NAME).upload(path, file_bytes)
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
    client.storage.from_(bucket).upload(path, file_bytes, options)
    return path