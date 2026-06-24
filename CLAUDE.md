# CLAUDE.md — vgi-secretscan

Contributor/agent notes. User-facing docs live in `README.md`; this is the
"how it's built and where the sharp edges are" companion. This worker is
modeled on [`vgi-opa`](https://github.com/Query-farm/vgi-opa)'s **offline
scalar** family and [`vgi-threatintel`](https://github.com/Query-farm/vgi-threatintel)'s
**table function** (the `secret_scan` emitter mirrors `reputation()`), and the
domain shape ("scan text → structured findings") follows
[`vgi-ioc`](https://github.com/Query-farm/vgi-ioc)'s `extract_iocs`.

## What this is

A [VGI](https://query.farm) worker (Go) that scans text / source code for
**leaked secrets** using the embedded **gitleaks** ruleset + Shannon-entropy
heuristics, exposed as DuckDB SQL functions. Detection is **pure and offline**
(no network) and **never verifies** whether a secret is live. Output is always
the **redacted** match. Built on the [`vgi-go`](https://github.com/Query-farm/vgi-go)
SDK over stdio. Catalog name: `secretscan`.

## Layout

```
cmd/vgi-secretscan-worker/main.go   stdio entry point; assembles the worker + catalog
internal/secretworker/
  scan.go                           the offline core: Scan / Contains, redaction,
                                    entropy, confidence scoring (gitleaks-backed)
  functions.go                      the scalar + table VGI functions + Register(w)
  scan_test.go                      pure-function tests (positive/negative fixtures,
                                    redaction invariant, offsets, entropy, redact)
  functions_test.go                 VGI Process-path tests + RegisterDoesNotPanic
test/sql/secretscan.test            haybarn-unittest sqllogictest — authoritative E2E
Makefile                            build / test-unit / test-sql / lint
```

There is **no mock server** (like vgi-opa, unlike vgi-threatintel) — detection
is pure/offline, so the E2E points haybarn straight at the worker binary.

## The detection core (`scan.go`, read first)

- **`Scan(text) ([]Finding, error)`** — runs the gitleaks detector over the
  string and maps each `report.Finding` to a redaction-safe `Finding`
  (`rule_id`, `description`, `match_redacted`, `start_offset`, `entropy`,
  `confidence`), sorted by offset. Empty text → no findings.
- **`Contains(text) (bool, error)`** — cheap predicate; true iff ≥1 finding.
- The gitleaks `*detect.Detector` is built **once** via `sync.Once`
  (`NewDetectorDefaultConfig()` parses the embedded `gitleaks.toml` through
  viper). Building per-call would re-parse 220+ rules every batch. We set
  `MaxTargetMegaBytes = 0` so large blobs are scanned in full.
- **Redaction (`redactMatch`/`Redact`)**: the raw secret never leaves the
  process. `gitleaks` returns both `Match` (matched text, may include context)
  and `Secret` (the credential substring); we replace `Secret` inside `Match`
  with a fixed-width mask. ≤8 chars → all `*`; longer → first4 + `********` +
  last4. The fixed mask hides the secret's exact length.
- **Entropy**: gitleaks only computes entropy for rules with an entropy
  threshold, so when its `Entropy` is 0 we fall back to our own
  `ShannonEntropy(secret)` — callers always get a usable number to threshold on.
- **Confidence (`scoreConfidence`)**: structurally-distinctive rules
  (AWS/GCP/Azure/GitHub/GitLab/Slack/Stripe/private-key/JWT) → 0.95; other named
  rules → 0.85; `generic-api-key`/entropy rules → 0.30–0.75 scaled by entropy.
  This is a heuristic on top of gitleaks, not a gitleaks field.
- **`offsetOf`**: gitleaks reports `StartLine`/`StartColumn` (1-based, per
  line); we recompute the absolute **byte** offset with `strings.Index(text,
  match)` to avoid column-arithmetic off-by-ones across multibyte runes.

## The VGI functions (`functions.go`)

- **`secret_contains(text) -> BOOLEAN`** — a `vgi.ScalarFunction` implemented
  directly (`Name/Metadata/ArgumentSpecs/OnBind/Process`). `OnBind` returns
  `vgi.BindResult(arrow.FixedWidthTypes.Boolean)`; `Process` uses
  `vgi.MapColumn(params, batch, 0, array.NewBooleanBuilder, fn)`. Holds **no
  state** — the gob gotcha does not apply.
- **`secret_scan(text) -> rows`** — a `vgi.TypedTableFunc[secretScanState]`.
  `OnBind` returns `vgi.BindSchema(secretScanSchema)` (explicit schema). The
  `text` arg is derived via `vgi.DeriveArgSpecs`/bound via `vgi.BindArgs`.

### GOB-STATE GOTCHA (cost hours elsewhere — heed it)

Table-function state is **gob-encoded** by the SDK between `NewState` and
`Process` (it may cross an HTTP process boundary). State must hold only
**exported, gob-encodable** fields — no `arrow.Record`, interface, channel,
func, or unexported field, or vgi-go **panics at `RegisterTable`**.
`secretScanState` embeds `Cursor{ Rows []Finding; Offset int }` — `Finding` is
all exported scalar fields, so it gobs cleanly. We compute the findings eagerly
in `NewState` and rebuild the Arrow batch in `Process`. `TestRegisterDoesNotPanic`
guards this.

**Streaming state MUST carry an explicit cursor, not a bare `Done bool`** (the
HTTP-continuation invariant). Over the **stateless HTTP transport** the worker
keeps no live state between `Process` ticks — the framework round-trips the
producer state through a continuation token (gob-snapshotting the user state each
tick, emitting ≤1 data batch per response, resuming from the token). A `Done`
flag flipped *after* the single `Emit` observes the pre-`Emit` snapshot on
resume, re-emits the same rows forever, and pins the worker in an infinite loop
(subprocess/unix hold live state in memory, so they never hit it). `secret_scan`
emits one row per finding (a blob can hold many), so this is mandatory. The fix:
the embedded `Cursor` whose `Process` emits a bounded slice from `Offset`,
advances `Offset` **before** yielding, and `out.Finish()`es when `Offset >=
len(Rows)`. The framework snapshots `Offset` into the token, so HTTP resumes
correctly and terminates. `TestCursorSurvivesContinuation` guards this.

## Sharp edges

1. **gitleaks-as-library.** Use `github.com/zricethezav/gitleaks/v8/detect`
   (`NewDetectorDefaultConfig`, `DetectString`) and `.../report` (the `Finding`
   struct). The default ruleset is **embedded** in the gitleaks package
   (`//go:embed gitleaks.toml`), so there is nothing to ship alongside the
   binary.
2. **gitleaks allowlists doc placeholders.** Several canonical example secrets
   are allowlisted upstream and will NOT fire — notably the AWS docs key
   `AKIAIOSFODNN7EXAMPLE` and the `ghp_` placeholder. Test fixtures use *other*
   fake-but-non-allowlisted values (e.g. `AKIAZ3MZ7EXAMPLE4Q2T`). If a fixture
   mysteriously returns 0 findings, check the upstream allowlist first.
3. **NULL scalar inputs short-circuit.** DuckDB does not invoke a scalar's
   `Process` for a NULL row — `secret_contains(NULL)` returns **NULL**, not
   `false`. The `.test` asserts `NULL`. (`Process` still null-guards defensively
   for direct unit-test calls.)
4. **`haybarn-unittest` silently SKIPS `require vgi`.** Under haybarn the
   extension is not autoloaded for `require`, so a `.test` using `require vgi`
   is skipped (looks green but ran nothing). Use an explicit `statement ok` /
   `LOAD vgi;` instead. The `.test` here `require-env VGI_SECRETSCAN_WORKER` and
   `ATTACH 'secretscan' AS secretscan (TYPE vgi, LOCATION '${VGI_SECRETSCAN_WORKER}')`.
5. **Offsets are bytes, not chars.** `start_offset` is a byte offset; the
   multi-secret `.test` case asserts the exact post-newline byte position.
6. **Stable assertions.** SQL assertions check `rule_id`, `match_redacted`,
   `start_offset`, `confidence`, and counts (deterministic). They avoid
   asserting the exact floating `entropy` value (only `entropy > 3.0`).

## Out of scope (intentional)

- **No verification** of whether a found secret is live — noisy and fraught; see
  README. Findings are *candidate* leaks.
- **No git-history / repo scanning** — this scans the text passed to it; use the
  gitleaks CLI for repos.

## Test inventory

- **Go (`make test-unit`)** — `scan_test.go`: positive fixtures (fake AWS key,
  Slack token, RSA private-key header, JWT), the **never-leaks-raw-secret**
  invariant, clean-text negatives, `Contains`, byte `start_offset`, `Redact`,
  and `ShannonEntropy`. `functions_test.go`: drives `secret_contains`'s
  `Process` (positive/negative/NULL) and `RegisterDoesNotPanic` (the gob guard).
- **SQL (`make test-sql`)** — `test/sql/secretscan.test`: `secret_contains`
  true/false/NULL + a column WHERE-filter; `secret_scan` count, redacted-match,
  offset, confidence threshold, raw-secret-absence, entropy>3, multi-secret
  ordering, and empty/NULL → zero rows. 26 assertions.

## Maintenance

Rulesets drift; bump `github.com/zricethezav/gitleaks/v8` periodically and
re-run `make test`. Ongoing maintenance, not a data business.

## Conventions

- Source files start with `// Copyright 2026 Query Farm LLC - https://query.farm`.
- `gofmt`, `go vet`, and `go test ./...` must be clean before committing.
- The worker is MIT-licensed; it embeds the gitleaks engine + ruleset (MIT,
  Copyright 2019 Zachary Rice) plus the vgi-go SDK for the protocol.
