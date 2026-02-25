# syntax=docker/dockerfile:1.6
# Enable BuildKit features for multi-platform builds and enhanced security

# =============================================================================
# Build Arguments
# =============================================================================
ARG BUILD_DATE
ARG VERSION=bf8035d
ARG VCS_REF=bf8035d826e8a5b9a473c387b66df690f67e8c4b
ARG BUILDPLATFORM

# =============================================================================
# Build stage
# =============================================================================
FROM python:3.11-slim-bookworm AS builder

# Re-declare ARGs for this stage
ARG BUILD_DATE
ARG VERSION
ARG VCS_REF

WORKDIR /app

# Security: Create non-root user for build process
RUN groupadd -r builder && useradd -r -g builder builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libxml2-dev \
    libxslt1-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create virtual environment with proper permissions
RUN python -m venv /opt/venv && \
    chown -R builder:builder /opt/venv

# Switch to non-root user for pip operations
USER builder
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY --chown=builder:builder requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Switch back to root for library collection
USER root

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
    cp /lib64/ld-linux-x86-64.so.2 /opt/libs/ 2>/dev/null || cp /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /opt/libs/ && \
    # Set ownership for copied files
    chown -R root:root /opt/libs /opt/python && \
    # Create tmp directory for runtime stage
    mkdir -p /opt/tmp && chmod 1777 /opt/tmp

# =============================================================================
# Distroless runtime stage
# =============================================================================
FROM gcr.io/distroless/cc-debian12

# Re-declare ARGs for this stage
ARG BUILD_DATE
ARG VERSION
ARG VCS_REF

# Security: OCI Labels for image metadata and traceability
LABEL org.opencontainers.image.source="https://github.com/peedy2495/rc-unlock.git" \
      org.opencontainers.image.description="Remote LUKS unlock tool for initramfs" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="peedy2495" \
      org.opencontainers.image.title="rc-unlock" \
      org.opencontainers.image.documentation="https://github.com/peedy2495/rc-unlock/blob/main/README.md"

WORKDIR /app

# Security: Copy tmp directory for read-only filesystem compatibility
# Created in builder stage since distroless has no mkdir
COPY --from=builder /opt/tmp /tmp

# Copy system libraries
COPY --from=builder /opt/libs/* /lib/x86_64-linux-gnu/

# Copy ld-linux to correct location
COPY --from=builder /opt/libs/ld-linux-x86-64.so.2 /lib64/

# Copy Python
COPY --from=builder /opt/python/bin/python3.11 /usr/local/bin/python3.11
COPY --from=builder /opt/python/lib/python3.11 /usr/local/lib/python3.11

# Copy virtual environment
COPY --from=builder /opt/venv /opt/venv

# Security: Copy application with specific ownership and permissions
# 65532:65532 is the distroless non-root user/group
# 644 permissions: owner read/write, group read, others read
COPY --chown=65532:65532 --chmod=644 rc-unlock.py interactive_shell.py .

# Set environment - include venv site-packages in Python path
ENV PATH="/opt/venv/bin:/usr/local/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="/opt/venv/lib/python3.11/site-packages" \
    LD_LIBRARY_PATH="/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu"

# Security: Run as non-root (distroless uses 65532:65532)
USER 65532:65532

# Security: HEALTHCHECK for container monitoring
# Uses Python to verify the application can start and import dependencies
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/python3.11", "-c", "import yaml, paramiko; import sys; sys.exit(0)"]

# Set entrypoint using system Python with venv packages
ENTRYPOINT ["/usr/local/bin/python3.11", "rc-unlock.py"]