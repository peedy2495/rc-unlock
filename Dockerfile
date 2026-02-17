# Build stage
FROM python:3.11-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libxml2-dev \
    libxslt1-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Collect all required libraries and binaries
RUN mkdir -p /opt/libs /opt/python/lib /opt/python/bin && \
    # Copy Python interpreter
    cp /usr/local/bin/python3.11 /opt/python/bin/ && \
    # Copy Python libraries
    cp /usr/local/lib/libpython3.11.so.1.0 /opt/libs/ && \
    # Copy Python standard library (entire directory)
    cp -r /usr/local/lib/python3.11 /opt/python/lib/ && \
    # Collect all .so files from venv
    find /opt/venv -name "*.so" -exec cp {} /opt/libs/ \; && \
    # Collect all .so files from Python's lib-dynload
    find /usr/local/lib/python3.11/lib-dynload -name "*.so" -exec cp {} /opt/libs/ \; && \
    # Collect all required system libraries using ldd
    for lib in /opt/libs/*.so; do \
        ldd "$lib" 2>/dev/null | grep "=> /" | awk '{print $3}' >> /tmp/deps.txt; \
    done && \
    ldd /opt/python/bin/python3.11 2>/dev/null | grep "=> /" | awk '{print $3}' >> /tmp/deps.txt && \
    # Copy unique dependencies
    cat /tmp/deps.txt | sort -u | while read lib; do \
        if [ -f "$lib" ] && [ ! -f "/opt/libs/$(basename $lib)" ]; then \
            cp "$lib" /opt/libs/; \
        fi; \
    done && \
    # Copy ld-linux
    cp /lib64/ld-linux-x86-64.so.2 /opt/libs/ 2>/dev/null || cp /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /opt/libs/

# Distroless runtime stage
FROM gcr.io/distroless/cc-debian12

WORKDIR /app

# Copy system libraries
COPY --from=builder /opt/libs/* /lib/x86_64-linux-gnu/

# Copy ld-linux to correct location
COPY --from=builder /opt/libs/ld-linux-x86-64.so.2 /lib64/

# Copy Python
COPY --from=builder /opt/python/bin/python3.11 /usr/local/bin/python3.11
COPY --from=builder /opt/python/lib/python3.11 /usr/local/lib/python3.11

# Copy virtual environment
COPY --from=builder /opt/venv /opt/venv

# Copy application
COPY rc-unlock.py .

# Set environment - include venv site-packages in Python path
ENV PATH="/opt/venv/bin:/usr/local/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="/opt/venv/lib/python3.11/site-packages" \
    LD_LIBRARY_PATH="/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu"

# Run as non-root (distroless uses 65532:65532)
USER 65532:65532

# Set entrypoint using system Python with venv packages
ENTRYPOINT ["/usr/local/bin/python3.11", "rc-unlock.py"]
