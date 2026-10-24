# syntax=docker/dockerfile:1

# Stage 1: build the web interface.
FROM node:22-slim AS ui
WORKDIR /build/ui
# There is no lockfile yet, so versions are resolved from the ranges in package.json when the image is built.
COPY ui/package.json ./
RUN npm install --no-audit --no-fund
COPY ui/tsconfig.json ui/build.mjs ui/index.html ./
COPY ui/public ./public
COPY ui/src ./src
RUN node build.mjs

# Stage 2: the server, with the built interface next to it.
FROM python:3.12-slim AS runtime
# Pass --build-arg WITH_EMBEDDINGS=true to add fastembed (dense retrieval). Untested in this image; see the README.
ARG WITH_EMBEDDINGS=false
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN if [ "$WITH_EMBEDDINGS" = "true" ]; then pip install ".[embeddings]"; else pip install .; fi
COPY examples ./examples
COPY --from=ui /build/ui/dist ./ui-dist

# The server runs as an ordinary user and writes only to /data (and /tmp).
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
 && mkdir -p /data \
 && chown app:app /data

ENV HIPAA_AUDIT_STATIC_DIR=/app/ui-dist \
    HIPAA_AUDIT_DB_PATH=/data/audits.sqlite3
USER app
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"]

ENTRYPOINT ["hipaa-audit"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
