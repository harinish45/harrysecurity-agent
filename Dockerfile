# syntax=docker/dockerfile:1.7
# NEXUS-STRIKE production image: dependency build is isolated from runtime.
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml README.md ./
COPY nexus ./nexus
COPY web ./web
COPY scripts ./scripts
COPY docs ./docs
COPY knowledge ./knowledge
COPY prompts ./prompts

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir .

FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    dnsutils \
    iputils-ping \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r nexus \
    && useradd -r -g nexus -m -d /home/nexus nexus

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY nexus ./nexus
COPY scripts ./scripts
COPY web ./web
COPY docs ./docs
COPY knowledge ./knowledge
COPY prompts ./prompts
COPY pyproject.toml README.md ./
COPY engagements ./engagements
COPY reports ./reports

RUN mkdir -p /app/reports /app/engagements /app/logs /app/.nexus \
    && chown -R nexus:nexus /app

USER nexus

LABEL org.opencontainers.image.title="NEXUS-STRIKE" \
      org.opencontainers.image.description="AI-assisted cybersecurity assessment platform" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.authors="HARINISH" \
      org.opencontainers.image.licenses="MIT"

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8765/ || exit 1

# Deployment should additionally set --read-only, --cap-drop=ALL,
# --security-opt=no-new-privileges and a bounded memory/CPU limit.
CMD ["python", "-m", "web.server"]
