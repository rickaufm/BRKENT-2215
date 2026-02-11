# Cisco Meraki MCP Server - Dockerfile
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv (modern Python package manager)
RUN pip install uv

# Install Python dependencies directly (system-wide)
RUN uv pip install --system fastmcp>=0.5.0 httpx>=0.28.1 python-dotenv>=1.0.0 uvicorn>=0.30.6

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash app && \
    chown -R app:app /app
USER app

# Expose the HTTP server port
EXPOSE 8000

# Set environment variables
ENV PYTHONPATH=/app
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8000

# Run the Meraki MCP server
CMD ["python", "meraki_mcp_server.py"]
