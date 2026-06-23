#!/usr/bin/env bash
# Copyright 2026 Query Farm LLC - https://query.farm
#
# Run this repo's sqllogictest suite (test/sql/*.test) against the
# vgi-secretscan VGI worker, using a prebuilt standalone `haybarn-unittest` and
# the signed community `vgi` extension — no C++ build from source. See
# ci/README.md.
#
# Secret detection is pure/offline (the gitleaks ruleset is embedded in the
# worker binary), so there is NO mock server — the suite points haybarn straight
# at the worker binary, mirroring `make test-sql`.
#
# Required environment:
#   HAYBARN_UNITTEST       path to the haybarn-unittest binary
#   VGI_SECRETSCAN_WORKER  worker LOCATION the .test files ATTACH (the built Go
#                          worker binary the vgi extension spawns over stdio)
# Optional:
#   STAGE                  scratch dir for the preprocessed test tree (default: mktemp)
set -euo pipefail

: "${HAYBARN_UNITTEST:?path to the haybarn-unittest binary}"
: "${VGI_SECRETSCAN_WORKER:?worker LOCATION (the built Go worker binary)}"

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
STAGE="${STAGE:-$(mktemp -d)}"

# --- Stage the preprocessed tests -------------------------------------------
echo "Staging preprocessed tests into $STAGE ..."
mkdir -p "$STAGE/test/sql"
for f in "$REPO"/test/sql/*.test; do
  awk -f "$HERE/preprocess-require.awk" "$f" > "$STAGE/test/sql/$(basename "$f")"
done

cd "$STAGE"

# Warm the extension cache once: vgi from the signed community channel. A miss
# here is only a warning — the per-test LOAD vgi; (the .test files load it
# explicitly) is what actually gates each file, and it needs vgi already
# INSTALLed into the runner's extension dir.
echo "Warming the extension cache (vgi from community) ..."
mkdir -p "$STAGE/test"
cat > "$STAGE/test/_warm.test" <<'EOF'
# name: test/_warm.test
# group: [warm]
statement ok
INSTALL vgi FROM community;
EOF
"$HAYBARN_UNITTEST" "test/_warm.test" >/dev/null 2>&1 || echo "::warning::extension warm step did not fully succeed"
rm -f "$STAGE/test/_warm.test"

# Run the whole suite in one invocation, streaming the runner's native
# sqllogictest report. Any failed assertion exits non-zero and fails the job.
echo "Running suite (worker: $VGI_SECRETSCAN_WORKER) ..."
"$HAYBARN_UNITTEST" "test/sql/*"
