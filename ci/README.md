# CI: the vgi-secretscan worker integration suite

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs the Go unit
tests and this repo's sqllogictest suite (`test/sql/*.test`) against the
vgi-secretscan VGI worker through the **real DuckDB `vgi` extension** on every
push / PR.

## How it works (no C++ build)

Rather than building the vgi DuckDB extension from source, CI drives a
**prebuilt** standalone `haybarn-unittest` (the DuckDB/Haybarn sqllogictest
runner, published in Haybarn's releases) and installs the **signed** `vgi`
extension from the Haybarn community channel:

1. **Build the worker** — `go build -o vgi-secretscan-worker
   ./cmd/vgi-secretscan-worker`. The resulting binary is a self-contained stdio
   worker the extension can spawn; `VGI_SECRETSCAN_WORKER` (an absolute path) is
   the ATTACH `LOCATION`. The gitleaks ruleset is embedded in the binary, so
   detection is fully offline — there is no mock server.
2. **Download the runner** — the `haybarn_unittest-linux-amd64.zip` asset from
   the latest Haybarn release.
3. **Preprocess** — [`preprocess-require.awk`](preprocess-require.awk) rewrites
   any `require <ext>` gate into an explicit signed `INSTALL <ext> FROM
   {community,core}; LOAD <ext>;`. This repo's tests already use an explicit
   `LOAD vgi;` (haybarn silently *skips* `require vgi`), so the awk is mostly a
   pass-through here; `require-env` and everything else pass through untouched.
4. **Run** — [`run-integration.sh`](run-integration.sh) stages the preprocessed
   tree, points `VGI_SECRETSCAN_WORKER` at the built worker binary, warms the
   extension cache once (`INSTALL vgi FROM community`), then runs the suite in a
   single `haybarn-unittest` invocation. Any failed assertion exits non-zero and
   fails the job.

## Run it locally

```bash
go build -o vgi-secretscan-worker ./cmd/vgi-secretscan-worker
# point HAYBARN_UNITTEST at a haybarn-unittest binary (or a local DuckDB
# `unittest` built with the vgi extension):
HAYBARN_UNITTEST=/path/to/haybarn-unittest \
VGI_SECRETSCAN_WORKER="$PWD/vgi-secretscan-worker" \
  ci/run-integration.sh
```

Or use the Makefile target (`make test-sql`), which builds the worker and points
it at `$(CURDIR)/vgi-secretscan-worker` with `haybarn-unittest` on `PATH`.
