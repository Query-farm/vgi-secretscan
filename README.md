# vgi-secretscan

[![CI](https://github.com/Query-farm/vgi-secretscan/actions/workflows/ci.yml/badge.svg)](https://github.com/Query-farm/vgi-secretscan/actions/workflows/ci.yml)

A [VGI](https://query.farm) worker, written in **Go**, that scans free text and
source code for **leaked secrets** — cloud keys (AWS / GCP / Azure),
GitHub / GitLab / Slack tokens, private keys, JWTs, and high-entropy strings —
all exposed as DuckDB/SQL functions. Detection uses the embedded
[**gitleaks**](https://github.com/gitleaks/gitleaks) ruleset (220+ rules) plus
Shannon-entropy heuristics.

Detection is **pure and fully offline** (no network) and the worker **never
returns the raw secret** — every match is **redacted**. It also **never
verifies** whether a found secret is live (see *Out of scope* below).

Built on the [`vgi-go`](https://github.com/Query-farm/vgi-go) SDK; speaks the
VGI protocol over stdio. Catalog name: `secretscan`.

```sql
INSTALL vgi FROM community; LOAD vgi;

-- LOCATION is the path to the compiled worker binary.
ATTACH 'secretscan' AS secretscan (TYPE vgi, LOCATION '/path/to/vgi-secretscan-worker');

-- Cheap predicate: does this text contain any secret? (great in a WHERE clause)
SELECT secretscan.secret_contains('deploy AKIAZ3MZ7EXAMPLE4Q2T now');  -- true

-- Find every secret, one row per finding (redacted match only).
SELECT rule_id, match_redacted, start_offset, entropy, confidence
FROM secretscan.secret_scan('SLACK_TOKEN=xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx');
-- slack-bot-token | xoxb********UvWx | 12 | 5.02 | 0.95
```

> The secrets shown throughout this README are **fake, non-live** test fixtures.

## Functions

| Function | Returns | Description |
| --- | --- | --- |
| `secret_contains(text VARCHAR)` | `BOOLEAN` | True if `text` contains at least one detectable secret. Cheap predicate for filtering. |
| `secret_scan(text VARCHAR)` | table | One row per finding. Columns below. |

`secret_contains` is a **scalar** (positional-only argument — VGI scalars never
take `name := value`). `secret_scan` is a **table function** whose `text`
argument is a bind-time constant (DuckDB table functions take literal, not
per-row, arguments — see *Per-column scanning* below).

### `secret_scan` output schema

| Column | Type | Meaning |
| --- | --- | --- |
| `rule_id` | `VARCHAR` | gitleaks rule id, e.g. `aws-access-token`, `slack-bot-token`, `private-key`, `jwt`, `generic-api-key`. |
| `description` | `VARCHAR` | Human-readable rule description. |
| `match_redacted` | `VARCHAR` | The matched text with the **secret portion masked** (`AKIA********4Q2T`). **Never the raw secret.** |
| `start_offset` | `INTEGER` | 0-based byte offset of the match within the input. |
| `entropy` | `DOUBLE` | Shannon entropy (bits/char) of the secret. Random/encoded values score high (~4–6); prose scores low. |
| `confidence` | `DOUBLE` | 0..1 heuristic confidence (see below). |

### Redaction

The raw secret never leaves the worker process. A secret of 8 characters or
fewer is masked entirely (`********`); a longer one keeps a 4-char prefix and
suffix with a fixed-width mask in between (`AKIA********4Q2T`). The fixed mask
means the redaction does not even reveal the secret's exact length. Any
surrounding context the rule matched (e.g. an assignment prefix) is preserved so
you can see *where* the secret was without seeing *what* it was.

### Confidence

`confidence` lets you threshold noisy findings:

- **0.95** — structurally distinctive, high-precision rules (a fixed prefix like
  `AKIA`/`ghp_`/`xoxb-`, a PEM header, a JWT shape): AWS/GCP/Azure, GitHub,
  GitLab, Slack, Stripe, private keys, JWTs.
- **0.85** — other named-provider rules.
- **0.30–0.75** — catch-all `generic-api-key` / entropy rules, scaled by
  entropy. These are the noisy ones.

```sql
-- Only structurally-certain leaks:
SELECT * FROM secretscan.secret_scan(:blob) WHERE confidence >= 0.9;
```

## Per-column scanning

`secret_contains` is a scalar, so it filters a whole column directly:

```sql
SELECT id FROM documents WHERE secretscan.secret_contains(body);
```

`secret_scan` is a table function and DuckDB passes it **literal** arguments
(not a column reference), so to expand findings across a table, scan per row in
the host application, or filter first with `secret_contains` and scan the
flagged rows. (This is the same shape as other VGI table functions such as
`vgi-threatintel`'s `reputation()`.)

## Behavior & robustness

- **Offline & deterministic.** No network call. Detection is deterministic for a
  given input and ruleset version.
- **Redacted output only.** The raw secret never appears in any output column.
- **NULL-safe.** `secret_contains(NULL)` is `NULL` (DuckDB short-circuits NULL
  scalar inputs); `secret_scan(NULL)` yields zero rows. Neither errors.
- **Embedded ruleset.** The gitleaks default ruleset (220+ rules) is compiled
  into the binary — no external config file to ship or load.

## Out of scope (by design)

- **No verification.** The worker does **not** test whether a found credential
  is live (no API calls to AWS/GitHub/etc.). Verification is noisy, slow, and
  fraught (it can trip alerts, get you rate-limited, or be interpreted as misuse
  of a credential), so it is deliberately excluded. Treat findings as *candidate*
  leaks to triage.
- **No git-history / repo scanning.** This worker scans the text you pass it.
  Use the upstream gitleaks CLI for scanning git history, diffs, and directories.

## Maintenance note

Secret-detection rulesets **drift**: providers add new token formats and
deprecate old ones. Keeping detection current means periodically bumping the
embedded gitleaks dependency (`go get github.com/zricethezav/gitleaks/v8@latest`)
and re-running the tests. This is ongoing **maintenance**, not a data feed — there
is no subscription or hosted dataset behind it.

## Build

Requires Go 1.25+.

```sh
make build        # builds ./vgi-secretscan-worker
```

The `vgi-secretscan-worker` binary speaks the VGI protocol over stdio; point a
DuckDB `ATTACH ... (TYPE vgi, LOCATION '…')` at it.

## Test

```sh
make test-unit    # pure-Go unit tests (detection is offline)
make test-sql     # haybarn-unittest SQL end-to-end
make test         # both
```

`make test-sql` needs [`haybarn-unittest`](https://query.farm) on `PATH`:

```sh
uv tool install haybarn-unittest
export PATH="$HOME/.local/bin:$PATH"
```

It builds the worker and runs the SQL suite against it (no mock server is needed
— detection is pure/offline).

## Licensing

- This worker is licensed **MIT** — see [`LICENSE`](./LICENSE).
- It embeds the [**gitleaks**](https://github.com/gitleaks/gitleaks) detection
  engine and its default ruleset (`github.com/zricethezav/gitleaks/v8`), which
  is licensed **MIT** (Copyright 2019 Zachary Rice). The embedded
  `config/gitleaks.toml` ruleset ships under the same MIT terms.
- gitleaks pulls in supporting libraries — `BobuSumisu/aho-corasick` (MIT),
  `wasilibs/go-re2` (a RE2 binding, Apache-2.0 / BSD components), and others —
  whose licenses are recorded in `go.sum` / their respective repositories.
- It is built on the [`vgi-go`](https://github.com/Query-farm/vgi-go) SDK (and
  its Apache Arrow dependency) for the VGI protocol — see that repo for its terms.
