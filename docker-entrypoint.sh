#!/bin/sh
# Copyright 2026 Query Farm LLC - https://query.farm
#
# Dispatch the single vgi-secretscan image into one of its transports:
#   http   (default) the HTTP server on $PORT (8000), bound 0.0.0.0 so a
#                    published host port reaches it. Serves /health.
#   stdio            a worker DuckDB spawns over stdio (on-host execution).
#   unix <path>      the AF_UNIX launcher transport on the given socket path.
# Any other first argument is exec'd verbatim (escape hatch for debugging).
#
# The worker is stateless (embedded gitleaks ruleset, offline detection), so
# there is no /data to create and no state env to wire — each mode just exec's
# the binary.
set -e

case "${1:-http}" in
  http)
    shift 2>/dev/null || true
    # vgi-go's RunHttp binds EXACTLY the address --http-addr names; the binary's
    # default 127.0.0.1:0 is loopback + ephemeral (right for dev/CI). In a
    # container we must bind 0.0.0.0 on a FIXED port so `-p $PORT:$PORT` and the
    # HEALTHCHECK reach it.
    exec vgi-secretscan-worker --http --http-addr "0.0.0.0:${PORT:-8000}" "$@"
    ;;
  stdio)
    shift 2>/dev/null || true
    exec vgi-secretscan-worker "$@"
    ;;
  unix)
    shift 2>/dev/null || true
    exec vgi-secretscan-worker --unix "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
