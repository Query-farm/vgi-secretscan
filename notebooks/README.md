# Secret Scanner example

[01 · Keep the evidence behind a secret-review queue](01_keep_evidence_behind_a_review_queue.ipynb)
uses visible SQL to preserve missing-input and no-match distinctions, retain every redacted
finding through a registry join, and compare the full evidence with a confidence-based review queue.
The existing analytical story and release-limit controls are retained.

Read saved outputs directly on GitHub, or use **Open in Colab**, run the install cell, then Run All.
A single downloaded notebook retrieves and SHA-256-verifies its original synthetic fixture through
shared `prepare("secretscan")`, pinned to public commit
`1621fdd53ee79fbc03e5d5b8fb8a08090c4d0210`. There is no private source, local worker build or
provider account requirement. Actual hosted Colab remains untested; a fresh preloaded Python 3.12
notebook-only execution validates this bootstrap path.

## Locked local runner

Install [uv](https://docs.astral.sh/uv/), then run from this directory:

```sh
uv sync --locked --extra runner
uv run --locked --extra runner vgi-notebooks
```

The [shared tools v0.3.18](https://github.com/Query-farm/vgi-example-notebooks/tree/v0.3.18) supply
compact SQL setup, branding and SVG presentation; the optional `[runner]` extra is for local
publication. Colab installs only the base package and accepts compatible preloaded plotting/data
libraries. The local lock records exact dependencies. Python 3.11+ is supported; uv can install it.

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'secretscan' (TYPE vgi, LOCATION 'github-auto://Query-farm/vgi-secretscan@v0.4.0');
```

First setup downloads packages, the VGI extension, public fixture and pinned native worker.
Detection is then offline. No Go toolchain is needed. `connect(globals())` uses an in-memory database
with empty temporary SQL-secret storage, persistent secrets disabled and no JupySQL default
connection autoload. Cleanup closes it and removes the temporary secret directory. The notebook
never reads a user's repositories, environment secrets or accounts.

Optional Jupyter kernel:

```sh
uv run --locked --extra runner python -m ipykernel install --user \
  --name vgi-secretscan-notebooks --display-name 'Python (vgi-secretscan notebooks)'
```

Restart and run all after changes. Parameters, installation and analytical SQL remain visible;
Python setup/presentation/verification cells carry folding metadata. Defaults retain SVG MIME plus
committed `charts/` image references for GitHub. Experiment copies retain native SVG without
unpublished URLs. Logs, separate runs and PNG/SVG review exports are ignored under `validation/`
and `artifacts/`.

## One-parameter experiment

```sh
uv run --locked --extra runner vgi-notebooks \
  --parameters '{"MIN_CONFIDENCE":0.90}' --output-dir validation/high-confidence
```

The default 0.70 threshold selects all four findings. Raising it to 0.90 selects two: AWS and Slack
remain selected; npm and the generic assignment remain visible below threshold. Raw findings,
input audit, registry gaps, entropy and repeated-offset controls must remain unchanged. Confidence
accepts finite numeric values 0–1, excluding booleans. Restore 0.70 for default publication.

Overrides require a separate destination. Unknown parameter names, source-overwriting destinations
and invalid values fail without replacing successful default or experiment outputs. The complete
notebook directory runs independently of the worker checkout; copies carry their fixture and notes.

## Portable worker and provenance


The literal SQL location is `github-auto://Query-farm/vgi-secretscan@v0.4.0`. VGI downloads, verifies and caches the native release. It was executed on macOS Apple silicon; other platform archives appear on the release page. Haybarn 2.0.0rc11 is pinned in the independent notebook lock. Upgrade explicitly by changing the release and rerunning both settings.

`fixtures/synthetic-candidates.txt` is authored UTF-8 text containing four non-live credential-shaped strings and a non-ASCII heading. The AWS, Slack and npm shapes follow the repository's existing test/example fixtures; the generic assignment is authored for this notebook. The notebook adds ordinary prose, the AWS documentation placeholder, empty text and SQL NULL as controls. A separate two-line repeated AWS fixture illustrates an offset limitation; it is excluded from the main four-finding analysis. There is no public-data capture or live credential verification.

The detailed table function requires a bind-time constant. The setup reads the committed fixture and escapes single quotes into one SQL literal, used by the visible `secret_scan` call. The scalar `secret_contains` separately scans a whole SQL column. An exact-input assertion checks that both paths use the same fixture. Materialization keeps DataFrame display from repeating the detailed scan.

## Interpretation and limits

Confidence is the worker's heuristic, not a calibrated probability, severity or credential-validity estimate. The generic rule's actual score (about 0.736 here) differs from its registry representative score (0.64). Filtering uses the actual finding score. Entropy does not rank candidates in the same order as confidence.

The registry contains eleven curated rules, not the full detector engine. The npm finding has no matching registry row, so a left join preserves it with NULL provider/category. The chart labels that reporting group explicitly and retains it when its selected count reaches zero. Unknown registry metadata is not a negative finding.

Redacted matches retain prefix/suffix characters and may include assignment context. They are not full anonymization and are not unique identifiers. The notebook checks that none of its four complete synthetic values appear in the returned redacted matches. Raw fixture strings remain readable in the input file; never replace these committed inputs with real credentials and publish their contents.

`start_offset` is a zero-based UTF-8 byte offset of the matched text, which can begin before the credential itself. The fixture checks the difference from character position. In v0.4.0, repeated identical matches are located using the first occurrence: the separate probe returns two rows but both report offset 7. This existing release limitation is demonstrated explicitly; offsets and redacted strings must not be used to deduplicate occurrences. `finding_id` is only a local display index for one execution.

No finding, including the deliberately allowlisted documentation placeholder, is not proof of safety. NULL input remains unknown. These authored inputs cannot measure detection precision/recall or justify a production queue threshold, and no candidate's validity is tested against a provider.

## Coverage and validation

[coverage.json](coverage.json) maps all **3/3 named surfaces** to visible executed SQL and interpreted
results: scalar `secret_contains`, table function `secret_scan` and native view `secret_detectors`.
Complete function/table/view exports are retained under [coverage/](coverage/); there are zero
physical tables and one native view. The current source registration has the same names and
signatures. Its release-to-current changes are metadata/examples, including a clarified private-key
block description in the curated registry; scanning/scoring and dependencies are unchanged.
Coverage is three exact released-runtime demonstrations and zero exact current-runtime executions,
with current-interface compatibility reviewed separately. It does not mean every detector was tested.

Both parameter settings pass 12 SQL checks plus population/selection reconciliation, exact-input,
UTF-8 offset and fixture-redaction checks. The complete raw findings and input/offset displays
remain identical across the experiment. Four runner guards preserve successful outputs. All four
chart renderings are inspected, and the published GitHub SVG images are checked in a browser.

Existing green [source CI 43580447714](https://github.com/Query-farm/vgi-secretscan/actions/runs/43580447714)
is reused for unchanged worker source. No worker build or repeated source/transport suite runs for
this notebook-only change. Notebook lint, presentation, coverage receipts and full default/experiment
execution are checked. The known repeated-offset limitation remains documented, not repaired.
Source, tests, Go manifests and root locks are preserved.

See the [shared standard](https://github.com/Query-farm/vgi-example-notebooks/blob/v0.3.18/docs/standard.md).
