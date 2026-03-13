FROM python:3.12-slim

WORKDIR /app

# Install analyzer first
COPY analyzer/ /analyzer/
RUN pip install --no-cache-dir -e /analyzer

# Install backend deps
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY backend/ .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
