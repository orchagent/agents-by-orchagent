FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY pyproject.toml ./
COPY src ./src

RUN pip install --no-cache-dir .

CMD ["sh", "-c", "uvicorn billing_doc_analyzer.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
