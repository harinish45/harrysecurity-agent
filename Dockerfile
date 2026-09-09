# syntax=docker/dockerfile:1.7
# NEXUS-STRIKE production image: dependency build is isolated from runtime.
# Default CMD runs the web dashboard; the `nexus` CLI is also installed and
# fully usable by overriding CMD (e.g. `docker run <image> nexus --help`).
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching. Installs from the LOCK file
# (fully pinned, including transitive deps) for a reproducible build —
# requirements.txt's loose `>=` pins (now just `-e .[dev]`, see
# requirements.txt) are for local dev only.
COPY requirements.lock.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.lock.txt

# Copy the package and install it. --no-deps: dependencies are already
# pinned and installed from the lock file above; without this, pip would
# resolve pyproject.toml's own loose `>=` dependency specifiers again and
# could silently pull a newer, unpinned version of something the lock
# file fixed, defeating the point of installing from the lock file at all.
COPY pyproject.toml README.md ./
COPY nexus ./nexus
COPY web ./web
COPY scripts ./scripts
COPY docs ./docs
COPY knowledge ./knowledge
COPY prompts ./prompts
RUN pip install --no-cache-dir --no-deps --prefix=/install .

FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/usr/local/bin:$PATH"

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

# Installed packages from the builder's --prefix=/install go straight onto
# the runtime image's real site-packages/bin layout (/usr/local), not a
# separate venv path — the builder never created a venv, so copying to
# /opt/venv here would silently leave PATH pointing at an empty directory.
COPY --from=builder /install /usr/local
COPY --from=builder /build/nexus ./nexus
COPY --from=builder /build/scripts ./scripts
COPY --from=builder /build/web ./web
COPY --from=builder /build/docs ./docs
COPY --from=builder /build/knowledge ./knowledge
COPY --from=builder /build/prompts ./prompts
COPY --from=builder /build/pyproject.toml /build/README.md ./
COPY requirements.txt ./

RUN mkdir -p /app/reports /app/engagements /app/logs /app/.nexus \
    && chown -R nexus:nexus /app

USER nexus

LABEL org.opencontainers.image.title="NEXUS-STRIKE" \
      org.opencontainers.image.description="The Ultimate AI-Powered Cybersecurity Platform" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.authors="HARINISH" \
      org.opencontainers.image.licenses="MIT"

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8765/ || exit 1

# Deployment should additionally set --read-only, --cap-drop=ALL,
# --security-opt=no-new-privileges and a bounded memory/CPU limit.
CMD ["python", "-m", "web.server"]
