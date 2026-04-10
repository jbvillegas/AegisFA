import os
from dotenv import load_dotenv
from app import create_app

# Load local environment variables from .env before app initialization.
load_dotenv()

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '5009')), debug=True)
