import os
from dotenv import load_dotenv
from app import create_app

# Load local environment variables from .env before app initialization.
# Wrap in try-except to handle macOS file-sharing I/O issues
try:
    load_dotenv()
except OSError:
    pass  # If .env cannot be read, rely on environment variables from docker-compose

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '5001')), debug=True)
