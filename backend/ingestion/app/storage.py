import os
from supabase import create_client

_supabase = None

BUCKET_NAME = os.getenv("SUPABASE_BUCKET_NAME", "log-files")

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