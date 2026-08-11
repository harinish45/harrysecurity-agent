# ============================================================
# NEXUS-STRIKE — Multi-stage Docker build
# Stage 1: builder — install dependencies
# Stage 2: runtime — minimal image with non-root user
# ============================================================

# ── Stage 1: Builder ──────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Copy the package and install it
COPY . .
RUN pip install --no-cache-dir --prefix=/install .

# ── Stage 2: Runtime ──────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="NEXUS-STRIKE" \
      org.opencontainers.image.description="The Ultimate AI-Powered Cybersecurity Platform" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.authors="HARINISH" \
      org.opencontainers.image.licenses="MIT"

# Install runtime dependencies (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    dnsutils \
    iputils-ping \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r nexus && useradd -r -g nexus -m -d /home/nexus nexus

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application files
COPY --from=builder /build/nexus /app/nexus
COPY --from=builder /build/scripts /app/scripts
COPY --from=builder /build/web /app/web
COPY --from=builder /build/docs /app/docs
COPY --from=builder /build/knowledge /app/knowledge
COPY --from=builder /build/prompts /app/prompts
COPY --from=builder /build/engagements /app/engagements
COPY --from=builder /build/reports /app/reports
COPY --from=builder /build/pyproject.toml /app/
COPY --from=builder /build/requirements.txt /app/
COPY --from=builder /build/README.md /app/

# Create writable directories for the non-root user
RUN mkdir -p /app/reports /app/engagements /app/logs \
    && chown -R nexus:nexus /app

# Switch to non-root user
USER nexus

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8765/ || exit 1

# Expose dashboard port
EXPOSE 8765

# Default command
ENTRYPOINT ["nexus"]
CMD ["--help"]