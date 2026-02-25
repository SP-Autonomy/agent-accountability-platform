FROM python:3.11-slim

WORKDIR /app

COPY saas/services/detections/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the saas package (services + shared)
COPY saas/__init__.py /app/saas/__init__.py
COPY saas/services/ /app/saas/services/

# Copy labs package (scenarios runner)
COPY labs/__init__.py /app/labs/__init__.py
COPY labs/scenarios/ /app/labs/scenarios/

ENV PYTHONPATH=/app
ENV DATABASE_URL=postgresql://aiaap:aiaap@postgres:5432/aiaap
ENV CORRELATION_INTERVAL_SECONDS=10
ENV IDENTITY_URL=http://identity:8300

EXPOSE 8200

CMD ["uvicorn", "saas.services.detections.main:app", "--host", "0.0.0.0", "--port", "8200"]
