FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libxml2-dev \
    libxslt1-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r unlocker && useradd -r -g unlocker unlocker

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the script
COPY rc-unlock.py .

# Make script executable and set permissions
RUN chmod +x rc-unlock.py && \
    chown -R unlocker:unlocker /app

# Switch to non-root user
USER unlocker

# Set entrypoint
ENTRYPOINT ["python", "rc-unlock.py"]
