FROM python:3.11-slim as builder

WORKDIR /app

# Install compilation essentials (if any dependencies require native extensions)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY src/requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final minimal execution stage
FROM python:3.11-slim

WORKDIR /home/appuser/app

# Create a secure system user & group (uid:gid = 1000:1000 to match default Raspberry Pi systems)
RUN groupadd -g 1000 appuser && \
    useradd -r -u 1000 -g appuser -d /home/appuser -s /sbin/nologin appuser && \
    mkdir -p /home/appuser/app /logs /geolite /data && \
    chown -R appuser:appuser /home/appuser /logs /geolite /data

# Copy built python packages from builder stage
COPY --from=builder --chown=appuser:appuser /root/.local /home/appuser/.local
COPY --chown=appuser:appuser src/ /home/appuser/app/

# Expose local pathing to python executable
ENV PATH=/home/appuser/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1

USER appuser

VOLUME ["/logs", "/geolite", "/data"]

CMD ["python3", "main.py"]
