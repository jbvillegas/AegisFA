from supabase import create_client, Client
import os
from typing import Optional, Dict, List

class SupabaseDB:
    def __init__(self):
        self.supabase: Optional[Client] = None
        self.init_client()

    def init_client(self):
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_KEY")
        if not url or not key:
            raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set in environment variables.")
        self.supabase = create_client(url, key)
        print("Supabase client connected.")

    def save_log(self, source: str, raw_data: Dict, normalized_data: Dict, natural_language_summary: str, timestamp: str) -> Dict:
        data = {
            "source": source,
            "raw_data": raw_data,
            "normalized_data": normalized_data,
            "natural_language_summary": natural_language_summary,
            "timestamp": timestamp,
            "created_at": timestamp
        }

        response = self.supabase.table("logs").insert(data).execute()
        return response.data[0] if response.data else None
    
    def get_logs(self, search_text: str) -> List[Dict]:
        response = self.supabase.table("logs").select("*").ilike("natural_language_summary", f"%{search_text}%").execute()
        return response.data

    _db = None

    def get_supabase_db() -> 'SupabaseDB':
        global _db
        if _db is None:
            _db = SupabaseDB()
        return _db