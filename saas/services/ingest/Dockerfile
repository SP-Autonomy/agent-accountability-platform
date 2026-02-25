FROM python:3.11-slim

WORKDIR /app

COPY saas/services/ingest/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the saas package (services + shared)
COPY saas/__init__.py /app/saas/__init__.py
COPY saas/services/ /app/saas/services/

ENV PYTHONPATH=/app
ENV DATABASE_URL=postgresql://aiaap:aiaap@postgres:5432/aiaap
ENV TENANT_ID=default

EXPOSE 8100

CMD ["uvicorn", "saas.services.ingest.main:app", "--host", "0.0.0.0", "--port", "8100"]
