FROM python:3.11-slim

WORKDIR /app

COPY saas/services/dashboard/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Dashboard is self-contained — talks to other services via HTTP (INGEST_URL etc.)
COPY saas/services/dashboard/ /app/

# Shared read-only modules needed at runtime (no DB imports, pure stdlib)
COPY saas/services/shared/compliance.py /app/compliance.py

ENV PYTHONPATH=/app
ENV INGEST_URL=http://ingest:8100
ENV DETECTIONS_URL=http://detections:8200
ENV IDENTITY_URL=http://identity:8300

EXPOSE 8501

CMD ["streamlit", "run", "dashboard.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]
