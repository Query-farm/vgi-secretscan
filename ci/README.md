# CI: the vgi-secretscan worker integration suite

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs the Go unit
tests and this repo's sqllogictest suite (`test/sql/*.test`) against the
vgi-secretscan VGI worker through the **real DuckDB `vgi` extension** on every
push / PR.

## Transport matrix

The same SQL suite runs over **every transport the vgi extension supports**, as
a GitHub Actions matrix (`SQL E2E (subprocess)`, `SQL E2E (http)`,
`SQL E2E (unix)`). The transport is selected by the `TRANSPORT` env var passed
to [`run-integration.sh`](run-integration.sh), which only changes what the
`.test` files ATTACH as the worker `LOCATION` (the vgi extension picks the
transport from that string):

| `TRANSPORT`  | Worker launch                                                | `VGI_SECRETSCAN_WORKER` (ATTACH LOCATION) |
| ------------ | ------------------------------------------------------------ | ----------------------------------------- |
| `subprocess` | extension spawns the binary over stdio                       | `/abs/path/to/vgi-secretscan-worker`      |
| `http`       | `vgi-secretscan-worker --http` (prints `PORT:<n>`)           | `http://127.0.0.1:<port>`                 |
| `unix`       | `vgi-secretscan-worker --unix <sock>` (prints `UNIX:<path>`) | `unix://<sock>`                           |

Port/socket discovery: for **http** the script parses the `PORT:<n>` line the
SDK prints on stdout (`vgi/worker.go` `RunHttp`); for **unix** it waits for the
`UNIX:<path>` line *and* for the socket file to exist before running the suite.
The HTTP `LOCATION` is the **bare** `scheme://host:port` with no path — the
extension POSTs each RPC method at `<LOCATION>/<method>` (e.g.
`/catalog_attach`), and the Go SDK mounts those at the server root; appending a
`/vgi` path would 404 every method.

**No mock server in any leg.** Secret detection is pure/offline (the gitleaks
ruleset is embedded in the worker binary), so unlike the data-fetching workers
there is nothing to start besides the worker itself (for http/unix, started
out-of-band and trap-killed on exit).

The **full** suite (`secretscan.test`) runs over all three transports — **no
tests are gated**.

### HTTP transport specifics

The **http** leg needs `httpfs` loaded, handled by `run-integration.sh`
automatically: the vgi extension drives the worker-RPC HTTP POSTs through
DuckDB's `HTTPUtil`, which is only registered once the signed core `httpfs`
extension is loaded. The `.test` files only `LOAD vgi`, so for the http leg the
script injects `INSTALL httpfs FROM core; LOAD httpfs;` after each `LOAD vgi;`
in the staged copies. Without it every worker request fails with an
`HTTP`-flavoured error that the runner silently skips. (The worker itself makes
*no* outbound network calls — `httpfs` is only the client DuckDB uses to talk to
the worker over the HTTP transport.)

#### Streaming table functions over HTTP (the cursor pattern)

`secret_scan` emits one row per finding (a blob can hold many) across multiple
`Process` exchanges. Over the **stateless** HTTP transport the worker holds no
live state between ticks — the framework round-trips the producer state through
an opaque continuation token (gob-encoding the user state after each tick,
emitting at most one data batch per response, then resuming from the token). The
position therefore **must live in the serialized state**: a bare post-`Emit`
`Done bool` observes the pre-`Emit` snapshot on resume, re-emits the same rows
forever, and pins the worker in an infinite loop (subprocess/unix keep the live
state in memory, so they were unaffected and hid the bug).

The fix is an explicit gob-encodable **cursor** in the state — `Cursor{ Rows
[]Finding; Offset int }` (in `internal/secretworker/functions.go`). `Process`
emits a bounded slice starting at `Offset`, advances `Offset` **before**
yielding, and calls `out.Finish()` once `Offset >= len(Rows)`. Because the
framework snapshots `Offset` into each continuation token, HTTP resumes from the
right row and terminates. `TestCursorSurvivesContinuation` guards this by
gob-round-tripping the state between every simulated tick. This is the reference
pattern for every streaming Go table function that must work over HTTP.

### Silent-skip guard (no fake passes)

The DuckDB/Haybarn sqllogictest runner **skips** (exit 0, not a failure) any
test whose error message matches a built-in network-error allowlist that
includes the substring `HTTP`. A broken HTTP transport would therefore report
"All tests were skipped" and the job would go *green having run nothing*.
`run-integration.sh` guards against this: it captures the runner output and
**fails the leg** if every test was skipped, surfacing the runner's skip
reason. A real run must print `All tests passed (N assertions ...)`.

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
   tree, resolves `VGI_SECRETSCAN_WORKER` for the selected transport, warms the
   extension cache once (`INSTALL vgi FROM community`), then runs the suite in a
   single `haybarn-unittest` invocation. Any failed assertion exits non-zero and
   fails the job. Any out-of-band worker is killed on exit.

## Run it locally

```bash
go build -o vgi-secretscan-worker ./cmd/vgi-secretscan-worker
# point HAYBARN_UNITTEST at a haybarn-unittest binary (or a local DuckDB
# `unittest` built with the vgi extension):
HAYBARN_UNITTEST=/path/to/haybarn-unittest \
VGI_SECRETSCAN_WORKER="$PWD/vgi-secretscan-worker" \
TRANSPORT=subprocess \
  ci/run-integration.sh   # or TRANSPORT=http / TRANSPORT=unix
```

Or use the Makefile target (`make test-sql`), which builds the worker and points
it at `$(CURDIR)/vgi-secretscan-worker` with `haybarn-unittest` on `PATH`.
