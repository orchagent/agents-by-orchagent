FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install git for cloning repos and npm for npm audit
RUN apt-get update && apt-get install -y git nodejs npm && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY src ./src

# Install the package and pip-audit for Python dependency scanning
RUN pip install --no-cache-dir . pip-audit

CMD ["sh", "-c", "uvicorn dep_scanner.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
