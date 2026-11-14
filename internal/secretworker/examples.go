// Copyright 2026 Query Farm LLC - https://query.farm

package secretworker

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/Query-farm/vgi-go/vgi"
)

// Example queries for every exposed object, defined ONCE here. Each object's
// native Examples slice and its vgi.example_queries tag are both rendered from
// the same []vgi.CatalogExample, so the SQL is byte-identical by construction
// (the loader dedupes the two carriers into one described example, VGI515).
//
// The composed examples combine two of the worker's own objects in one query —
// secret_scan's findings joined to the secret_detectors registry, and
// secret_contains run over secret_scan's redacted output. secret_scan only takes
// a constant literal (DuckDB rejects LATERAL column arguments for it), so every
// composition scans one literal and joins/aggregates around it. Each composed
// example appears in the schema-level list AND within the first five examples of
// the object that drives it (the agent simulator only shows object examples).

// sampleEnvText is a clearly-fake, .env-style fixture holding three secrets: an
// AWS access key id and a Slack bot token (both in the curated registry) and an
// npm token (a real gitleaks rule the curated registry does not list).
const sampleEnvText = "AWS_ACCESS_KEY_ID=AKIAZ3MZ7EXAMPLE4Q2T " +
	"SLACK_TOKEN=xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx " +
	"NPM_TOKEN=npm_Zq8xK2vN7rT4mW9pL3sY6bH1cJ5dF0gA8eRt"

// Composed example SQL (secret_scan x secret_detectors x secret_contains).
const (
	composedEnrichSQL = "SELECT f.rule_id, f.match_redacted, f.start_offset, d.provider, d.category " +
		"FROM secretscan.main.secret_scan('" + sampleEnvText + "') AS f " +
		"LEFT JOIN secretscan.main.secret_detectors AS d USING (rule_id) " +
		"ORDER BY f.start_offset;"

	composedRedactionCheckSQL = "SELECT count(*) AS findings, " +
		"bool_or(secretscan.main.secret_contains(f.match_redacted)) AS leaks_after_redaction " +
		"FROM secretscan.main.secret_scan('" + sampleEnvText + "') AS f;"

	composedCoverageSQL = "SELECT d.rule_id, d.provider, count(f.rule_id) > 0 AS detected " +
		"FROM secretscan.main.secret_detectors AS d " +
		"LEFT JOIN secretscan.main.secret_scan('" + sampleEnvText + "') AS f USING (rule_id) " +
		"WHERE d.confidence >= 0.9 " +
		"GROUP BY d.rule_id, d.provider " +
		"ORDER BY detected DESC, d.rule_id;"
)

var (
	composedEnrichExample = vgi.CatalogExample{
		SQL: composedEnrichSQL,
		Description: "Enrich each finding in a .env-style string with its provider and category from the " +
			"secret_detectors registry: AWS / Cloud Keys and Slack / Chat Tokens; the npm token's rule " +
			"(npm-access-token) is outside the curated registry, so its provider and category are NULL.",
	}
	composedRedactionCheckExample = vgi.CatalogExample{
		SQL: composedRedactionCheckSQL,
		Description: "Confirm the redacted output is safe to log: re-check every finding's match_redacted " +
			"with secret_contains (3 findings; leaks_after_redaction is FALSE, so no redacted match still " +
			"trips a detector).",
	}
	composedCoverageExample = vgi.CatalogExample{
		SQL: composedCoverageSQL,
		Description: "Coverage check: for each high-confidence (>= 0.9) detector in the registry, report " +
			"whether it fired on a .env-style string (aws-access-token and slack-bot-token are TRUE; the " +
			"other eight are FALSE).",
	}
)

// secretContainsExamples feed secret_contains' Examples + vgi.example_queries.
var secretContainsExamples = []vgi.CatalogExample{
	{
		SQL:         "SELECT secretscan.main.secret_contains('aws_secret = AKIAZ3MZ7EXAMPLE4Q2T') AS leaked;",
		Description: "Check whether a single string holds any detectable secret (returns TRUE here for the AWS-style key).",
	},
	{
		SQL:         "SELECT secretscan.main.secret_contains('just a harmless note, nothing to see here') AS leaked;",
		Description: "Check a benign string with no secret (returns FALSE).",
	},
}

// secretScanExamples feed secret_scan's Examples + vgi.example_queries.
var secretScanExamples = []vgi.CatalogExample{
	{
		SQL:         "SELECT rule_id, match_redacted, confidence FROM secretscan.main.secret_scan('aws_secret = AKIAZ3MZ7EXAMPLE4Q2T');",
		Description: "List each secret found in a string, with its rule, redacted match, and confidence.",
	},
	{
		SQL:         "SELECT rule_id, start_offset FROM secretscan.main.secret_scan('aws_secret = AKIAZ3MZ7EXAMPLE4Q2T') WHERE confidence >= 0.9;",
		Description: "List only the high-confidence findings (confidence >= 0.9) in a string, with each finding's byte offset.",
	},
	composedEnrichExample,
	composedRedactionCheckExample,
}

// secretScanExecutableExamples is secret_scan's vgi.executable_examples: the
// composed redaction check is offline and deterministic, so it ships with its
// expected result.
func secretScanExecutableExamples() string {
	type execExample struct {
		Description    string           `json:"description"`
		SQL            string           `json:"sql"`
		ExpectedResult []map[string]any `json:"expected_result"`
	}
	return marshalJSON([]execExample{{
		Description:    composedRedactionCheckExample.Description,
		SQL:            composedRedactionCheckExample.SQL,
		ExpectedResult: []map[string]any{{"findings": 3, "leaks_after_redaction": false}},
	}})
}

// detectorExamples feed the secret_detectors view's vgi.example_queries.
var detectorExamples = []vgi.CatalogExample{
	{
		Description: "Browse every detector this worker recognises, highest-confidence first.",
		SQL:         "SELECT rule_id, provider, category, confidence FROM secretscan.main.secret_detectors ORDER BY confidence DESC, rule_id;",
	},
	{
		Description: "List only the high-confidence structural detectors (confidence >= 0.9).",
		SQL:         "SELECT rule_id, provider FROM secretscan.main.secret_detectors WHERE confidence >= 0.9 ORDER BY rule_id;",
	},
	{
		Description: "Count the recognised detectors grouped by the provider family they cover.",
		SQL:         "SELECT category, count(*) AS detectors FROM secretscan.main.secret_detectors GROUP BY category ORDER BY detectors DESC, category;",
	},
	composedCoverageExample,
}

// schemaExamples is the representative list for the main schema's
// vgi.example_queries: one example per object, then the composed ones.
var schemaExamples = []vgi.CatalogExample{
	{
		SQL:         "SELECT secretscan.main.secret_contains('aws_secret = AKIAZ3MZ7EXAMPLE4Q2T') AS leaked;",
		Description: "Predicate: does this string hold any detectable secret? (Returns TRUE for the AWS-style key.)",
	},
	{
		SQL:         "SELECT rule_id, match_redacted, confidence FROM secretscan.main.secret_scan('aws_secret = AKIAZ3MZ7EXAMPLE4Q2T');",
		Description: "Enumerate each finding with its rule, redacted match, and confidence.",
	},
	{
		SQL:         "SELECT rule_id, provider, confidence FROM secretscan.main.secret_detectors ORDER BY confidence DESC, rule_id;",
		Description: "Browse the detector registry, highest-confidence first.",
	},
	composedEnrichExample,
	composedRedactionCheckExample,
	composedCoverageExample,
}

// SchemaExampleQueries renders the main schema's vgi.example_queries tag.
func SchemaExampleQueries() string { return exampleQueriesJSON(schemaExamples) }

// exampleQueriesJSON renders examples as the JSON list of {description, sql}
// objects vgi.example_queries requires (VGI502/503).
func exampleQueriesJSON(examples []vgi.CatalogExample) string {
	type ex struct {
		Description string `json:"description"`
		SQL         string `json:"sql"`
	}
	out := make([]ex, len(examples))
	for i, e := range examples {
		out[i] = ex{Description: e.Description, SQL: e.SQL}
	}
	return marshalJSON(out)
}

// marshalJSON encodes v without HTML escaping (so ">=" stays readable in the
// published tag) and panics on failure — inputs are static Go values.
func marshalJSON(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return strings.TrimSuffix(buf.String(), "\n")
}
