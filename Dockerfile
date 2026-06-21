# Use official lightweight Python image
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy and install python dependencies
COPY agent_tick/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all source files
COPY . /app

# Set env port variable (default to 8080 for Cloud Run)
ENV PORT=8080
ENV PYTHONPATH=/app

# Start uvicorn server
CMD ["sh", "-c", "uvicorn agent_tick.api:app --host 0.0.0.0 --port ${PORT}"]
