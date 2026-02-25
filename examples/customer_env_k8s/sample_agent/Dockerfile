FROM python:3.12-slim

WORKDIR /app

# Install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the sample agent
COPY app.py .

# Copy AIAAP SDK (optional — agent falls back to bare OTel if not present)
# In a real deployment: pip install aiaap-sdk or mount the SDK package
COPY --from=. . /app/connectors/ /app/connectors/ 2>/dev/null || true

EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
