# PIILeakTest Docker Image
FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/hkrishnan62/PIILeakTest"
LABEL org.opencontainers.image.description="ETL testing framework for detecting PII leakage"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md LICENSE ./
COPY piileaktest/ ./piileaktest/
COPY examples/ ./examples/
COPY sample_data/ ./sample_data/

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e .

# Create directories for output
RUN mkdir -p /data /reports

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PIILEAKTEST_OUTPUT_DIR=/reports

# Default command
ENTRYPOINT ["piileaktest"]
CMD ["--help"]

# Example usage:
# docker run -v $(pwd)/data:/data -v $(pwd)/reports:/reports piileaktest scan /data/file.csv
# docker run -v $(pwd):/workspace piileaktest run-suite /workspace/suite.yaml --output /reports
