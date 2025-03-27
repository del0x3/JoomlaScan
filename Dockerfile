FROM python:3.12-slim

LABEL maintainer="del <del@inlanefreight.local>" \
      version="2.0" \
      description="Modern Joomla vulnerability scanner with enhanced features and parallel scanning capabilities"

# Set Python environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2-dev \
    libxslt1-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY joomla_scanner.py comptotestdb.txt ./

# Make the script executable
RUN chmod +x joomla_scanner.py

# Set the entrypoint
ENTRYPOINT ["python", "joomla_scanner.py"]

# Default command (can be overridden)
CMD ["--help"] 