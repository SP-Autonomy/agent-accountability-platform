FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY normalizer.py container_forwarder.py ./

ENV PYTHONPATH=/app
ENV AWS_REGION=us-east-1
ENV POLL_INTERVAL_SECONDS=60

CMD ["python", "container_forwarder.py"]
