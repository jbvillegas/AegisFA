FROM mcr.microsoft.com/devcontainers/python:1-3.11-bullseye

ENV PYTHONUNBUFFERED=1

COPY ingestion/requirements.txt /tmp/pip-tmp/requirements-web.txt

RUN pip3 --disable-pip-version-check --no-cache-dir install -r /tmp/pip-tmp/requirements-web.txt \
   && rm -rf /tmp/pip-tmp

WORKDIR /workspaces/backend/ingestion
EXPOSE 5001
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--workers", "1", "--timeout", "120", "run:app"]
