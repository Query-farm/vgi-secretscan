# Copyright 2026 Query Farm LLC - https://query.farm
#
# Single image that serves the network transports of the `secretscan` VGI worker:
#   docker run ... IMG            -> HTTP server on $PORT      (default; serves /health)
#   docker run -i ... IMG stdio   -> stdio worker DuckDB spawns on-host
#   docker run ... IMG unix ...   -> AF_UNIX launcher transport
# See docker-entrypoint.sh.
#
# The worker is STATELESS: the gitleaks ruleset is embedded in the binary and
# detection is pure/offline (no network, no data files), so there is no /data
# volume and no `farm.query.vgi.volumes` mount-discovery label. The image is
# just the compiled binary + a tiny entrypoint.
# syntax=docker/dockerfile:1

# ---- build stage -----------------------------------------------------------
# CGO is REQUIRED: the vgi-go SDK links DuckDB (via duckdb/duckdb-go), so
# CGO_ENABLED=0 fails to select a platform binding. Pinned glibc (bookworm) so
# the binary links against the same libc the slim runtime ships. gcc/g++ back
# the cgo compile + C++ link of the embedded DuckDB.
FROM golang:1.26-bookworm AS build
WORKDIR /src

ENV CGO_ENABLED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Modules are fetched from the network (no vendor dir in this repo). Resolve the
# dependency graph first, on a BuildKit cache mount, so normal code edits reuse
# the downloaded module cache.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/

# BuildKit cache mounts persist the Go build + module caches across rebuilds, so
# incremental changes only recompile the changed packages and the CGO link, not
# the whole DuckDB-linked tree every time. The cache dir is ephemeral, so copy
# the binary out to a non-cache path before the layer ends.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go build -trimpath -ldflags="-s -w" \
        -o /out/vgi-secretscan-worker ./cmd/vgi-secretscan-worker

# ---- runtime stage ---------------------------------------------------------
# debian-slim (not distroless) so the HEALTHCHECK below has a real `curl`, and
# so the C++ runtime the CGO-linked DuckDB needs (libstdc++/libgcc) is present.
FROM debian:bookworm-slim

# Build metadata, wired from docker/metadata-action outputs in CI.
ARG VERSION=0.0.0
ARG GIT_COMMIT=unknown
ARG SOURCE_URL=https://github.com/Query-farm/vgi-secretscan

# Standard OCI labels + the VGI transport-advertisement label. `transports`
# lists the NETWORK transports this image serves (http); stdio and the AF_UNIX
# launcher socket are spawn/local modes, not published network transports.
LABEL org.opencontainers.image.title="vgi-secretscan" \
      org.opencontainers.image.description="Scan text/code for leaked secrets (gitleaks ruleset + entropy) as a VGI worker for DuckDB/SQL — offline, redacted output, no verification (stdio + HTTP)" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.licenses="MIT" \
      farm.query.vgi.transports='["http"]'

ENV PORT=8000 \
    # Build provenance only; the version the worker advertises over VGI comes
    # from catalog metadata, not this.
    VGI_SECRETSCAN_GIT_COMMIT=${GIT_COMMIT}

WORKDIR /app

# curl backs the HEALTHCHECK below; the CGO-linked binary needs libgcc/libstdc++
# (present in bookworm-slim's base, but pulled in explicitly to be safe).
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# `--chmod` sets the mode in the COPY layer itself; a separate `RUN chmod` would
# rewrite the ~100MB binary into a second overlay layer.
COPY --from=build --chmod=0755 /out/vgi-secretscan-worker /usr/local/bin/vgi-secretscan-worker
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Run unprivileged. No state, no volume — there is nothing to own or persist.
RUN useradd --create-home --uid 10001 app
USER app

EXPOSE 8000

# Readiness probe for HTTP mode. Inert for a short-lived stdio container (which
# has no HTTP server — the probe just fails harmlessly there).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS "http://localhost:${PORT:-8000}/health" || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["http"]
