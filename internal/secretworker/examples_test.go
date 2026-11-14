// Copyright 2026 Query Farm LLC - https://query.farm

package secretworker

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Query-farm/vgi-go/vgi"
)

// TestExampleTagsMatchNativeExamples guards VGI515 dedupe: each object's
// vgi.example_queries tag must carry exactly its native Examples, in order.
func TestExampleTagsMatchNativeExamples(t *testing.T) {
	for name, md := range map[string]vgi.FunctionMetadata{
		"secret_contains": (&SecretContainsFunction{}).Metadata(),
		"secret_scan":     (&SecretScanFunction{}).Metadata(),
	} {
		var got []struct{ Description, SQL string }
		if err := json.Unmarshal([]byte(md.Tags["vgi.example_queries"]), &got); err != nil {
			t.Fatalf("%s: bad vgi.example_queries JSON: %v", name, err)
		}
		if len(got) != len(md.Examples) {
			t.Fatalf("%s: %d tagged examples, %d native", name, len(got), len(md.Examples))
		}
		for i, e := range md.Examples {
			if got[i].SQL != e.SQL || got[i].Description != e.Description {
				t.Errorf("%s example %d: tag and native example differ", name, i)
			}
		}
	}
}

// TestComposedExamplesPlacement checks each composed example is in the
// schema-level list and within the first five examples of its driving object
// (the agent simulator shows only the first five per object).
func TestComposedExamplesPlacement(t *testing.T) {
	inFirstFive := func(list []vgi.CatalogExample, e vgi.CatalogExample) bool {
		for i, x := range list {
			if i < 5 && x.SQL == e.SQL {
				return true
			}
		}
		return false
	}
	cases := map[string][]vgi.CatalogExample{
		composedEnrichSQL:         secretScanExamples,
		composedRedactionCheckSQL: secretScanExamples,
		composedCoverageSQL:       detectorExamples,
	}
	for sql, driver := range cases {
		e := vgi.CatalogExample{SQL: sql}
		if !inFirstFive(driver, e) {
			t.Errorf("composed example not in its driver's first five: %s", sql)
		}
		if !inFirstFive(schemaExamples, e) && !strings.Contains(SchemaExampleQueries(), sql) {
			t.Errorf("composed example missing from schema list: %s", sql)
		}
	}
	var exec []map[string]any
	if err := json.Unmarshal([]byte(secretScanExecutableExamples()), &exec); err != nil || len(exec) != 1 {
		t.Fatalf("bad secret_scan executable examples: %v", err)
	}
}

// TestComposedRedactionInvariant is the Go-level twin of the composed
// redaction-check example: no redacted match re-trips a detector.
func TestComposedRedactionInvariant(t *testing.T) {
	findings, err := Scan(sampleEnvText)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("want 3 findings in sampleEnvText, got %d", len(findings))
	}
	for _, f := range findings {
		if ok, err := Contains(f.MatchRedacted); err != nil || ok {
			t.Errorf("redacted match %q still trips a detector (err=%v)", f.MatchRedacted, err)
		}
	}
}

// TestBarePEMHeaderNotDetected pins the registry's private-key description: the
// gitleaks rule needs the full BEGIN..END block, a header alone does not match.
func TestBarePEMHeaderNotDetected(t *testing.T) {
	ok, err := Contains("-----BEGIN RSA PRIVATE KEY-----")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("bare PEM header unexpectedly detected; update the private-key registry description")
	}
}
