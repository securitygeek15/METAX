FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8765

# Install runtime dependencies: libmagic for python-magic and curl for health check
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set up unprivileged user for secure execution
RUN groupadd -g 10001 metax && \
    useradd -u 10001 -g metax -s /bin/sh -m metax

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application sources
COPY --chown=metax:metax . .

# Directory for mounting evidence volumes
RUN mkdir -p /app/evidence && chown -R metax:metax /app

USER metax

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8765/api/status || exit 1

ENTRYPOINT ["python", "main.py"]
CMD ["--ui", "--no-browser", "--host", "0.0.0.0", "--port", "8765"]

