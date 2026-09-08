FROM mcr.microsoft.com/devcontainers/python:1-3.11-bullseye

ENV PYTHONUNBUFFERED=1

COPY ingestion/requirements.txt /tmp/pip-tmp/requirements-web.txt

RUN pip3 --disable-pip-version-check --no-cache-dir install -r /tmp/pip-tmp/requirements-web.txt \
   && rm -rf /tmp/pip-tmp

COPY ingestion /app/ingestion

WORKDIR /app/ingestion
EXPOSE 5001
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT:-5001} --workers 1 --threads 2 --timeout 120 run:app"]
