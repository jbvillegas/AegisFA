import contextlib

from dotenv import load_dotenv

from app import create_app

with contextlib.suppress(OSError):
    load_dotenv()

app = create_app()

if __name__ == "__main__":
    settings = app.config["SETTINGS"]
    app.run(host="0.0.0.0", port=settings.port, debug=settings.debug)
