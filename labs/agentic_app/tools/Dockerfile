FROM python:3.11-slim

WORKDIR /app

COPY labs/agentic_app/tools/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy OTel SDK connector package (connectors.code.otel_sdk_python)
COPY connectors/__init__.py /app/connectors/__init__.py
COPY connectors/code/__init__.py /app/connectors/code/__init__.py
COPY connectors/code/otel_sdk_python/ /app/connectors/code/otel_sdk_python/

# Copy tools app
COPY labs/agentic_app/tools/app.py .

ENV PYTHONPATH=/app
ENV AGENT_ID=tools-service

EXPOSE 9000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9000"]
