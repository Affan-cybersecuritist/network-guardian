# Use official Python runtime as base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire application
COPY . .

# Hugging Face Spaces (Docker SDK) expects the app on 7860 by default and
# doesn't set $PORT; Render (and most other hosts) inject $PORT at runtime.
# Defaulting to 7860 while still honoring $PORT covers both for free.
ENV PORT=7860
EXPOSE 7860

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import os, requests; requests.get('http://localhost:' + os.environ.get('PORT', '7860') + '/health', timeout=5)"

# Run the application with uvicorn (shell form so $PORT expands)
CMD uvicorn backend.main:app --host 0.0.0.0 --port ${PORT}
