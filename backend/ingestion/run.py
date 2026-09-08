from dotenv import load_dotenv
from app import create_app

try:
    load_dotenv()
except OSError:
    pass 

app = create_app()

if __name__ == '__main__':
    settings = app.config['SETTINGS']
    app.run(host='0.0.0.0', port=settings.port, debug=settings.debug)
