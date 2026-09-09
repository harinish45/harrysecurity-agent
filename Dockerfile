# ============================================================
# NEXUS-STRIKE — Multi-stage Docker build
# Stage 1: builder — install dependencies
# Stage 2: runtime — minimal image with non-root user
# ============================================================

# ── Stage 1: Builder ──────────────────────────────────────────
FROM python:3.10-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching. Installs from the LOCK file
# (fully pinned, including transitive deps) for a reproducible build —
# requirements.txt's loose `>=` pins are for local dev only.
COPY requirements.lock.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.lock.txt

# Copy the package and install it. --no-deps: dependencies are already
# pinned and installed from the lock file above; without this, pip would
# resolve pyproject.toml's own loose `>=` dependency specifiers again and
# could silently pull a newer, unpinned version of something the lock
# file fixed, defeating the point of installing from the lock file at all.
COPY . .
RUN pip install --no-cache-dir --no-deps --prefix=/install .

# ── Stage 2: Runtime ──────────────────────────────────────────
FROM python:3.10-slim AS runtime

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