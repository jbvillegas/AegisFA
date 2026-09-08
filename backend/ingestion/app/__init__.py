from flask import Flask
from supabase import create_client, Client
from .logging_config import setup_logging
from .config import Settings

supabase_client: Client = None

def create_app(settings: Settings | None = None):
    settings = settings or Settings.from_env()
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=settings.secret_key,
        MAX_CONTENT_LENGTH=settings.max_content_length,
        DEBUG=settings.debug,
        SETTINGS=settings,
    )

    global supabase_client
    supabase_client = create_client(
        settings.supabase_url,
        settings.supabase_service_role_key,
    )

    from .routes import main
    app.register_blueprint(main)

    return app