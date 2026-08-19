FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

WORKDIR /app/backend

# 8000 = dashboard/API, 2222 = decoy SSH honeypot
EXPOSE 8000 2222

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
