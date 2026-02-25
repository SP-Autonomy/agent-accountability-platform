FROM python:3.11-slim

WORKDIR /app

COPY labs/agentic_app/orchestrator/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy OTel SDK connector package (connectors.code.otel_sdk_python)
COPY connectors/__init__.py /app/connectors/__init__.py
COPY connectors/code/__init__.py /app/connectors/code/__init__.py
COPY connectors/code/otel_sdk_python/ /app/connectors/code/otel_sdk_python/

# Copy orchestrator app
COPY labs/agentic_app/orchestrator/app.py .

ENV PYTHONPATH=/app
ENV AGENT_ID=orchestrator-01
ENV AGENT_ROLE=orchestrator

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
