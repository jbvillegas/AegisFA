from flask import Flask
from supabase import create_client, Client
import os
from .logging_config import setup_logging

supabase_client: Client = None

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret')
    app.config['MAX_CONTENT_LENGTH'] = 120 * 1024 * 1024
    supabase_url = os.getenv('SUPABASE_URL')
    supabase_service_key = os.getenv('SUPABASE_SERVICE_ROLE_KEY')
    if not supabase_url or not supabase_service_key:
        raise RuntimeError(
            'Missing required environment variables: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY. '
            'Ensure backend/ingestion/.env is present or export these variables in your shell.'
        )

    global supabase_client
    supabase_client = create_client(
        supabase_url,
        supabase_service_key
    )

    from .routes import main
    app.register_blueprint(main)

    return app