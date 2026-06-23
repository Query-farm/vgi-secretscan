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
	// Accept --http for HTTP transport; default is stdio. Unknown launcher
	// flags are tolerated (the VGI extension varies argv to key its worker
	// cache), so we filter to flags we actually define before parsing.
	httpMode := flag.Bool("http", false, "Run as an HTTP server instead of stdio")
	logFlags := vgi.RegisterLoggingFlags(flag.CommandLine)
	_ = flag.CommandLine.Parse(filterKnownFlags(os.Args[1:], map[string]bool{
		"log-level":  true,
		"log-format": true,
		"log-logger": true,
	}))
	if err := logFlags.Apply(); err != nil {
		log.Fatalf("logging flags: %v", err)
	}

	w := vgi.NewWorker(
		vgi.WithCatalogName(secretworker.CatalogName),
		vgi.WithCatalogComment("Scan text/code for leaked secrets (gitleaks ruleset + entropy); redacted output, no verification"),
		vgi.WithCatalogTags(map[string]string{
			"source": "vgi-secretscan",
		}),
	)
	secretworker.Register(w)

	if *httpMode {
		if err := w.RunHttp("127.0.0.1:0"); err != nil {
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
