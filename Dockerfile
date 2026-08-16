# NEXUS-STRIKE production image
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Runtime packages required by networking/reporting dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    dnsutils \
    iputils-ping \
    netcat-openbsd \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r nexus && useradd -r -g nexus -m -d /home/nexus nexus

WORKDIR /app

# Copy source before installing so pyproject.toml is the single dependency source.
COPY pyproject.toml README.md ./
COPY nexus ./nexus
COPY scripts ./scripts
COPY web ./web
COPY docs ./docs
COPY knowledge ./knowledge
COPY prompts ./prompts
COPY engagements ./engagements
COPY reports ./reports

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir . \
    && mkdir -p /app/reports /app/engagements /app/logs \
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

# The container is a dashboard service; CLI commands remain available through `docker exec`.
CMD ["python", "-m", "web.server"]
