# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/root/.local/bin:/usr/local/bin:${PATH}" \
    PYTHONPATH="/app/src"

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        curl \
        ca-certificates \
        gdb \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install uv (Python package manager) and project dependencies
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    ~/.local/bin/uv pip install --system --no-cache-dir \
        "fastmcp>=0.3.2" \
        "mcp>=0.1.0" \
        "anyio>=4.2"

WORKDIR /app

COPY docs ./docs
COPY src ./src
COPY README.md ./README.md

ENTRYPOINT ["python", "src/mcp-gdb/server.py"]
