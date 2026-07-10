// Copyright 2026 Query Farm LLC - https://query.farm

package secretworker

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/Query-farm/vgi-go/vgi"
)

// A curated, browsable registry of the notable detector rules this worker
// recognises.
//
// WHY THIS EXISTS (VGI146): a worker whose only entry points are table
// functions forces an agent to already KNOW what the scanner detects (and a
// function's arguments) before it can retrieve anything. `secret_detectors` is
// a zero-argument, credential-free browsable relation — `SELECT * FROM
// secretscan.main.secret_detectors` returns the marquee gitleaks rules this
// worker flags, each with the provider it belongs to and the confidence tier it
// is assigned, so an agent can discover the detection surface before scanning.
// It is a pure VALUES list (no network, no gitleaks call), so it always scans.

// detectorRule is one row of the secret_detectors view: a gitleaks rule id, the
// provider/family it belongs to, a representative entropy used only to derive
// the confidence tier, and a one-line description. The Confidence column shown
// by the view is computed from scoreConfidence(RuleID, Entropy) so the view and
// the runtime scoring can never drift apart.
type detectorRule struct {
	RuleID      string
	Provider    string
	Category    string
	Entropy     float64 // representative entropy; 0 for fixed-prefix (structural) rules
	Description string
}

// detectorRegistry is the curated list surfaced by the secret_detectors view.
// Every rule id is a real gitleaks default-ruleset detector. The list is
// representative (the full ruleset has 200+ rules), chosen to span the marquee
// providers plus the generic/entropy catch-all so an agent sees the confidence
// tiers. Entropy is set only for the entropy-scaled generic rule; for the
// structural rules confidence is fixed regardless of entropy.
var detectorRegistry = []detectorRule{
	{"aws-access-token", "AWS", "Cloud Keys", 0, "AWS access key id (AKIA/ASIA...) — a structurally distinctive cloud credential."},
	{"gcp-api-key", "GCP", "Cloud Keys", 0, "Google Cloud Platform API key."},
	{"azure-ad-client-secret", "Azure", "Cloud Keys", 0, "Azure Active Directory client secret."},
	{"private-key", "PEM", "Private Keys", 0, "PEM-encoded private key header (RSA/EC/OPENSSH/PGP)."},
	{"github-pat", "GitHub", "VCS Tokens", 0, "GitHub personal access token (ghp_...)."},
	{"github-fine-grained-pat", "GitHub", "VCS Tokens", 0, "GitHub fine-grained personal access token (github_pat_...)."},
	{"gitlab-pat", "GitLab", "VCS Tokens", 0, "GitLab personal access token (glpat-...)."},
	{"slack-bot-token", "Slack", "Chat Tokens", 0, "Slack bot token (xoxb-...)."},
	{"stripe-access-token", "Stripe", "Payment Keys", 0, "Stripe secret API key (sk_live_.../sk_test_...)."},
	{"jwt", "JWT", "Tokens", 0, "JSON Web Token (three base64url segments separated by dots)."},
	{"generic-api-key", "Generic", "Entropy", 4.5, "Catch-all high-entropy api-key/secret assignment; confidence scales with entropy."},
}

// round2 rounds to two decimals for a stable DOUBLE literal in the view.
func round2(v float64) float64 { return math.Round(v*100) / 100 }

// sqlQuote renders a Go string as a single-quoted SQL literal.
func sqlQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// registryViewDefinition builds the VALUES-backed SELECT that defines the
// secret_detectors view. It has NO external dependency (pure literals) and does
// not call gitleaks, so it scans instantly with no network access or
// credentials. The confidence value is sourced from scoreConfidence so it stays
// in lockstep with the runtime confidence the scan functions emit.
func registryViewDefinition() string {
	var b strings.Builder
	b.WriteString("SELECT * FROM (VALUES\n")
	for i, r := range detectorRegistry {
		conf := round2(scoreConfidence(r.RuleID, r.Entropy))
		b.WriteString("  (")
		b.WriteString(sqlQuote(r.RuleID))
		b.WriteString(", ")
		b.WriteString(sqlQuote(r.Provider))
		b.WriteString(", ")
		b.WriteString(sqlQuote(r.Category))
		b.WriteString(", ")
		fmt.Fprintf(&b, "CAST(%g AS DOUBLE)", conf)
		b.WriteString(", ")
		b.WriteString(sqlQuote(r.Description))
		b.WriteString(")")
		if i < len(detectorRegistry)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString(") AS t(rule_id, provider, category, confidence, description)")
	return b.String()
}

// detectorExampleQueries serialises the view's object-level example queries as
// the JSON array of {description, sql} objects vgi.example_queries requires
// (VGI502/503). Every reference is fully catalog-qualified.
func detectorExampleQueries() string {
	type ex struct {
		Description string `json:"description"`
		SQL         string `json:"sql"`
	}
	out := []ex{
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
	}
	b, err := json.Marshal(out)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// RegisterRegistry registers the browsable secret_detectors view on the worker.
// It is a credential-free discovery relation (see the WHY note above) that
// satisfies VGI146 and gives agents a map of the detection surface before they
// scan any text with secret_contains / secret_scan.
func RegisterRegistry(w *vgi.Worker) {
	w.RegisterCatalogView("main", vgi.CatalogView{
		Name: "secret_detectors",
		Comment: "Curated registry of the notable gitleaks detector rules this worker flags " +
			"(rule_id, provider, category, confidence, description) — browse it to see the " +
			"detection surface before scanning with secret_contains / secret_scan.",
		Definition: registryViewDefinition(),
		ColumnComments: map[string]string{
			"rule_id":     "The gitleaks rule id this worker reports for the detector (matches secret_scan.rule_id).",
			"provider":    "The provider or credential family the detector covers (AWS, GitHub, Slack, ...).",
			"category":    "Broad grouping: Cloud Keys, VCS Tokens, Chat Tokens, Payment Keys, Private Keys, Tokens, or Entropy.",
			"confidence":  "The heuristic confidence in [0,1] this worker assigns a match of this rule; structural rules score 0.95, generic/entropy rules scale with entropy.",
			"description": "One-line description of what the detector matches.",
		},
		Tags: map[string]string{
			"vgi.title": "Recognised Secret Detectors",
			// VGI413: name one of the schema's vgi.categories entries.
			"vgi.category": "Findings",
			// VGI123 classifying tags (bare keys) for faceting, matching the schema.
			"domain":   "security",
			"category": "secret-detection",
			"topic":    "credential-leak-scanning",
			"vgi.keywords": `["detector","detectors","rule","ruleset","gitleaks rules","secret detectors",` +
				`"provider","confidence","registry","catalog","aws","github","slack","stripe","private key","jwt","generic api key"]`,
			"vgi.doc_llm": "A browsable, zero-argument catalog of the notable gitleaks detector rules " +
				"this worker recognises. Query it first to see what kinds of secrets are detected " +
				"(cloud keys, VCS tokens, chat tokens, payment keys, private keys, JWTs, and a " +
				"generic entropy catch-all), which provider each rule covers, and the confidence " +
				"tier a match earns. The rule_id column matches secret_scan.rule_id, so you can " +
				"map a scan finding back to its detector here. It is a static list, so it returns " +
				"instantly with no network access or credentials.",
			"vgi.doc_md": "## Recognised Secret Detectors\n\n" +
				"A browsable, zero-argument view listing the marquee [gitleaks](https://github.com/gitleaks/gitleaks) " +
				"detector rules this worker flags — a map of the detection surface for when you want to know " +
				"*what* is detected before scanning any text.\n\n" +
				"### Columns\n\n" +
				"- **`rule_id`** — the gitleaks rule id (matches `secret_scan.rule_id`).\n" +
				"- **`provider`** — the provider or credential family (AWS, GitHub, Slack, ...).\n" +
				"- **`category`** — a broad grouping (Cloud Keys, VCS Tokens, Chat Tokens, Payment Keys, Private Keys, Tokens, Entropy).\n" +
				"- **`confidence`** — the heuristic confidence in `[0,1]` a match of this rule earns (structural rules `0.95`; generic/entropy rules scale with entropy).\n" +
				"- **`description`** — a one-line summary of what the detector matches.\n\n" +
				"### Notes\n\n" +
				"The registry is a curated, representative slice of the full 200+-rule default ruleset, " +
				"not an exhaustive list. It is a static VALUES list, so it returns instantly with no network access. " +
				"Pick a `rule_id` here, then scan text with `secret_contains` / `secret_scan` and join the findings back on `rule_id`.",
			"vgi.example_queries": detectorExampleQueries(),
		},
	})
}
