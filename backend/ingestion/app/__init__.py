from flask import Flask
from supabase import create_client, Client
from flask_cors import CORS
from dotenv import load_dotenv
from .logging_config import setup_logging
import os

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
load_dotenv(os.path.join(basedir, '.env'))

supabase_client: Client = None

def create_app():
    app = Flask(__name__)
    CORS(app)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret')
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

    global supabase_client
    supabase_client = create_client(
        os.environ['SUPABASE_URL'],
        os.environ['SUPABASE_SERVICE_ROLE_KEY']
    )

    from .routes import main
    app.register_blueprint(main)

    return app
