// Copyright 2026 Query Farm LLC - https://query.farm

// Command vgi-secretscan-worker is a VGI worker that scans text / source code
// for leaked secrets — cloud keys (AWS/GCP/Azure), GitHub/Slack tokens, private
// keys, JWTs, high-entropy strings — using the embedded gitleaks ruleset plus
// Shannon-entropy heuristics, exposed as DuckDB SQL functions. Detection is
// pure and fully offline: no network, and it NEVER verifies whether a found
// secret is live. Output is always the REDACTED match. It speaks the VGI
// protocol over stdio.
package main

import (
	"flag"
	"log"
	"os"
	"strings"

	"github.com/Query-farm/vgi-go/vgi"
	"github.com/Query-farm/vgi-secretscan/internal/secretworker"
)

func main() {
	// Accept --http for HTTP transport and --unix for the AF_UNIX launcher
	// transport; default is stdio. Unknown launcher flags are tolerated (the
	// VGI extension varies argv to key its worker cache), so we filter to flags
	// we actually define before parsing.
	httpMode := flag.Bool("http", false, "Run as an HTTP server instead of stdio")
	unixPath := flag.String("unix", "", "Serve the AF_UNIX launcher transport on this socket path instead of stdio")
	logFlags := vgi.RegisterLoggingFlags(flag.CommandLine)
	_ = flag.CommandLine.Parse(filterKnownFlags(os.Args[1:], map[string]bool{
		"log-level":  true,
		"log-format": true,
		"log-logger": true,
		"unix":       true,
	}))
	if err := logFlags.Apply(); err != nil {
		log.Fatalf("logging flags: %v", err)
	}

	sourceURL := "https://github.com/Query-farm/vgi-secretscan"
	w := vgi.NewWorker(
		vgi.WithCatalogName(secretworker.CatalogName),
		vgi.WithCatalogComment("Scan text/code for leaked secrets (gitleaks ruleset + entropy); redacted output, no verification"),
		vgi.WithCatalogInfo(vgi.CatalogInfo{
			Name:      secretworker.CatalogName,
			SourceURL: &sourceURL,
		}),
		vgi.WithCatalogTags(map[string]string{
			"source":                 "vgi-secretscan",
			"vgi.title":              "Secret Scanner (gitleaks + entropy)",
			"vgi.keywords":           `["secret","secrets","secret scanning","leaked secret","credential","gitleaks","api key","access key","token","private key","jwt","entropy","redaction","security","detection","aws","gcp","azure","github","slack","stripe"]`,
			"vgi.doc_llm":            "Scan text or source code for leaked secrets — cloud keys (AWS/GCP/Azure), GitHub/Slack/GitLab/Stripe tokens, private keys, JWTs, and high-entropy strings — using the embedded gitleaks ruleset plus Shannon-entropy heuristics. Use secret_contains(text) as a cheap boolean predicate to filter rows that hold a secret, and secret_scan(text) to list each finding (rule, redacted match, byte offset, entropy, confidence). Detection is pure and fully offline: no network calls and it never verifies whether a secret is live; output is always the redacted match, never the raw credential.",
			"vgi.doc_md":             "# Secret Scanner — Detect Leaked API Keys, Tokens & Credentials in SQL\n\n![Gitleaks logo](https://gitleaks.io/logo.png)\n\nFind leaked secrets in text and source code directly from SQL: scan strings for AWS, GCP, and Azure cloud keys, GitHub, GitLab, Slack, and Stripe tokens, RSA/SSH private keys, JWTs, and high-entropy credentials — powered by the embedded [gitleaks](https://github.com/gitleaks/gitleaks) detection engine and delivered over Apache Arrow to DuckDB.\n\nThis extension is built for security, DevSecOps, and data engineers who need fast, in-database secret detection and credential-leak scanning without shipping sensitive data to an external service. Point it at a column of commit messages, log lines, config blobs, support tickets, or any free text, and it flags rows that contain leaked secrets so you can audit, redact, and remediate at the speed of a SQL query. Detection is **pure and fully offline** — it makes no network calls and **never verifies** whether a credential is live, so every finding is a *candidate* leak that is safe to surface in untrusted pipelines.\n\nUnder the hood the worker runs the [gitleaks](https://github.com/gitleaks/gitleaks) secret-scanning engine with its default ruleset of 200+ regular-expression detectors, embedded straight into the binary so there is nothing to download or configure. For generic and entropy-gated rules it layers a Shannon-entropy heuristic to score how random a candidate string looks, and it assigns each hit a `confidence` value so structurally-distinctive matches (a real-looking AWS access key) rank above noisy generic ones. Crucially, the **raw credential never leaves the process**: every reported match is redacted to a fixed-width mask that also hides the secret's true length. See the gitleaks [documentation](https://gitleaks.io) and the [default ruleset](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml) for the full detector catalog.\n\nThe extension exposes two functions. Use the scalar **`secret_contains(text)` → `BOOLEAN`** as a cheap predicate — ideal in a `WHERE` clause, e.g. `SELECT * FROM logs WHERE secret_contains(message)` — to filter the rows worth a deeper look. Then call the table function **`secret_scan(text)`** to enumerate findings: it emits one row per detected secret with `rule_id`, `description`, `match_redacted`, `start_offset` (a byte offset), `entropy`, and `confidence` (in `[0,1]`). `NULL` or empty input yields no findings, so the functions compose cleanly across large columns. For whole-repository or git-history scanning, reach for the gitleaks CLI; this worker scans the text you pass it.",
			"vgi.author":             "Query.Farm",
			"vgi.copyright":          "Copyright 2026 Query Farm LLC - https://query.farm",
			"vgi.license":            "MIT",
			"vgi.support_contact":    "https://github.com/Query-farm/vgi-secretscan/issues",
			"vgi.support_policy_url": "https://github.com/Query-farm/vgi-secretscan/blob/main/README.md",
		}),
		vgi.WithSchemaComments(map[string]string{
			"main": "Offline secret-detection functions (gitleaks ruleset + entropy); redacted output, no verification.",
		}),
		vgi.WithSchemaTags(map[string]map[string]string{
			"main": {
				"vgi.title":    "Secretscan — main",
				"vgi.keywords": `["secret","secrets","secret scanning","leaked secret","credential","gitleaks","api key","token","private key","jwt","entropy","redaction","security","secret_contains","secret_scan"]`,
				"vgi.doc_llm":  "Offline secret-detection functions over text and source code. secret_contains(text) returns a boolean for whether any secret is present; secret_scan(text) returns one row per detected secret with its rule, redacted match, byte offset, entropy, and a heuristic confidence score. No network, no verification, redacted output only.",
				"vgi.doc_md":   "## secretscan.main\n\nOffline secret-detection functions over text and source code, backed by the embedded [gitleaks](https://github.com/gitleaks/gitleaks) ruleset plus Shannon-entropy heuristics.\n\n### Functions\n\n- **`secret_contains(text)` → `BOOLEAN`** — a cheap predicate that returns `TRUE` when the text holds at least one detectable secret. Ideal in a `WHERE` clause to filter rows worth a deeper scan.\n- **`secret_scan(text)` → rows** — a table function emitting one row per finding (`rule_id`, `description`, `match_redacted`, `start_offset`, `entropy`, `confidence`).\n\n### Notes\n\nDetection is **pure and offline** (no network) and **never verifies** whether a secret is live — findings are *candidate* leaks. Output is always the **redacted** match; the raw credential never leaves the process.",
				// VGI123 classifying tags use BARE keys (not vgi.-namespaced).
				"domain":   "security",
				"category": "secret-detection",
				"topic":    "credential-leak-scanning",
				// VGI506 representative example queries (plain string, catalog-qualified).
				"vgi.example_queries": "SELECT secretscan.main.secret_contains('aws_secret = AKIAZ3MZ7EXAMPLE4Q2T');\n" +
					"SELECT rule_id, match_redacted, confidence FROM secretscan.main.secret_scan('aws_secret = AKIAZ3MZ7EXAMPLE4Q2T');\n" +
					"SELECT secret_contains('the quick brown fox') AS leaked;",
			},
		}),
	)
	secretworker.Register(w)

	if *httpMode {
		if err := w.RunHttp("127.0.0.1:0"); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *unixPath != "" {
		// AF_UNIX launcher transport: serve on the given socket path. The SDK
		// prints "UNIX:<path>" once listening; idleTimeout=0 disables the
		// self-shutdown timer (the launcher/CI owns the process lifecycle).
		if err := w.RunUnix(*unixPath, 0); err != nil {
			log.Fatal(err)
		}
		return
	}
	w.RunStdio()
}

// filterKnownFlags drops argv tokens for flags this binary doesn't define, so
// launcher-injected differentiation flags don't abort flag parsing. Flags named
// in valueFlags consume the following token as their value.
func filterKnownFlags(args []string, valueFlags map[string]bool) []string {
	defined := map[string]bool{}
	flag.CommandLine.VisitAll(func(f *flag.Flag) { defined[f.Name] = true })
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name := strings.TrimLeft(a, "-")
		hasInlineValue := strings.ContainsRune(name, '=')
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		if !defined[name] {
			continue
		}
		out = append(out, a)
		if valueFlags[name] && !hasInlineValue && i+1 < len(args) {
			i++
			out = append(out, args[i])
		}
	}
	return out
}
