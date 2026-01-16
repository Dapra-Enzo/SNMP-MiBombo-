FROM python:3.11-slim

# Install system dependencies
# libpcap-dev required for scapy
# iproute2 for ip command (if needed)
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose API port
EXPOSE 5000

# Default command (can be overridden)
CMD ["python", "main.py", "--api-only"]
