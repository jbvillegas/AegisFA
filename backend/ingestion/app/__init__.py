from flask import Flask
from supabase import create_client, Client
import os

supabase_client: Client = None

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret')

    global supabase_client
    supabase_client = create_client(
        os.environ['SUPABASE_URL'],
        os.environ['SUPABASE_SERVICE_ROLE_KEY']
    )

    from .routes import main
    app.register_blueprint(main)

    return app
