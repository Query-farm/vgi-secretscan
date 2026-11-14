# VGI SecretScan notebooks

[01 · Keep the evidence behind a secret-review queue](01_keep_evidence_behind_a_review_queue.ipynb) uses SQL to scan an authored fixture, preserve missing-input and no-match distinctions, enrich redacted findings without losing registry gaps, and visualize the effect of a confidence threshold.

## Run

Install [uv](https://docs.astral.sh/uv/), then from the repository root:

```sh
uv sync --project notebooks --frozen
uv run --project notebooks --frozen python notebooks/execute.py
```

The complete directory runs independently of the worker checkout:

```sh
cd notebooks
uv sync --frozen
uv run --frozen python execute.py
```

Initial setup downloads the locked Python dependencies, VGI community extension and pinned worker archive. Detection is then offline. No Go toolchain, local worker build, credentials or provider account is needed. All credential-shaped inputs are authored, non-live fixtures; the notebook never reads a user's repositories, environment secrets or accounts.

In VS Code choose `notebooks/.venv/bin/python` and use `notebooks/` as the working directory. Other Jupyter editors can register it:

```sh
uv run --project notebooks --frozen python -m ipykernel install --user --name vgi-secretscan-notebooks --display-name 'Python (vgi-secretscan notebooks)'
```

Restart and run all after changing the visible parameter. Connection and analytical SQL remain expanded. Imports, fixture quoting, plotting, generated interpretation, assertions and cleanup source are folded; chart outputs remain visible.

## Experiment

```sh
uv run --project notebooks --frozen python notebooks/execute.py \
  --parameters '{"MIN_CONFIDENCE":0.90}' \
  --output-dir notebooks/validation/high-confidence
```

The saved default uses 0.70. Raising it to 0.90 selects two of the same four findings instead of four: AWS and Slack remain selected, while npm and the generic assignment stay visible below threshold. Reset to 0.70 for the default.

The runner requires a different destination for overrides, rejects unknown names and only replaces notebook output after complete successful execution. Failures preserve prior saved outputs. Experiment copies include relative assets, fixtures, helpers, README and environment. Review charts, logs and experiment copies are ignored by Git.

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

## Validation

The polished default completed in 2.2 seconds and the detached 0.90 experiment in 1.7 seconds. Both passed 12 SQL checks plus population/selection reconciliation, exact-input, UTF-8 offset and fixture-redaction checks. Four final chart renderings and three runner preservation guards were reviewed. Input-audit, raw-findings and repeated-offset displays match across parameter settings.

Source validation passed 14 top-level Go tests (plus four positive-fixture subtests), 77 stdio / 79 HTTP / 77 Unix SQL assertions (one case each, no skips), the native build, vet, gofmt and golangci-lint. Executed metadata/AI validation passed at 95/100 L3 with zero findings. Notebook Ruff and structural review passed. The repeated-offset limitation is existing worker behavior and is not repaired by this documentation change. Source, tests, Go manifests and root lockfiles remain unchanged.

Official Query.Farm Strata Sun and VGI assets are copied unchanged, with linked Query.Farm branding at the top and final bottom.
