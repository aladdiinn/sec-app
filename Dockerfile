# ==============================================================================
# BSmart SOC Command Center — Production Dockerfile
# Optimized Multi-Stage Container for Ubuntu 22.04 LTS Deployment
# ==============================================================================

FROM python:3.11-slim-bookworm AS base

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install minimal OS dependencies for psycopg2 and networking
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    netcat-traditional \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency definition
COPY requirements.txt .

# Install Python packages
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Create non-root system user for security hardening
RUN groupadd -g 10001 socgroup && \
    useradd -u 10001 -g socgroup -s /bin/bash -m socuser

# Copy application code with proper permissions
COPY --chown=socuser:socgroup . .

# Ensure logs, data, and upload directories exist with writable permissions
RUN mkdir -p /app/logs /app/data && \
    chown -R socuser:socgroup /app/logs /app/data

# Switch to unprivileged user
USER socuser

# Expose internal FastAPI port (bound via HAProxy reverse proxy)
EXPOSE 8001

# Container healthcheck testing version endpoint
HEALTHCHECK --interval=15s --timeout=5s --retries=3 --start-period=15s \
    CMD curl -f http://127.0.0.1:8001/api/version || exit 1

# Start Uvicorn ASGI server with production proxy headers
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "4", "--proxy-headers", "--forwarded-allow-ips", "*"]
