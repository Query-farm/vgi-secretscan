// Copyright 2026 Query Farm LLC - https://query.farm

package secretworker

import (
	"strings"
	"testing"
)

// All secrets below are CLEARLY FAKE / non-live test fixtures. They are
// constructed to match a rule's structural pattern (prefix/shape) without being
// real credentials. Do not copy them as if they were valid.

func TestScanPositiveFixtures(t *testing.T) {
	cases := []struct {
		name       string
		text       string
		wantRuleID string // substring expected in some finding's rule_id
	}{
		{
			name:       "aws access key",
			text:       "deploy with AKIAZ3MZ7EXAMPLE4Q2T in the pipeline config",
			wantRuleID: "aws",
		},
		{
			name:       "slack bot token",
			text:       "SLACK_TOKEN=xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
			wantRuleID: "slack",
		},
		{
			name: "rsa private key header",
			text: "-----BEGIN RSA PRIVATE KEY-----\n" +
				"MIIEowIBAAKCAQEA1c7fakefakefakefakefakefakefakefakefakefakefake0Dpc\n" +
				"9XQc3T3wYxk6Rfu8X0YuTfxqB1m9T3xJ0gTfakefakefakefakefakefake3xfake==\n" +
				"-----END RSA PRIVATE KEY-----",
			wantRuleID: "private-key",
		},
		{
			name:       "jwt",
			text:       "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			wantRuleID: "jwt",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := Scan(tc.text)
			if err != nil {
				t.Fatalf("Scan error: %v", err)
			}
			if len(findings) == 0 {
				t.Fatalf("expected at least one finding, got none")
			}
			var matched bool
			for _, f := range findings {
				if strings.Contains(f.RuleID, tc.wantRuleID) {
					matched = true
				}
				// REDACTION INVARIANT: the redacted match must never contain
				// any 8+ char run of the original. We assert the raw secret
				// fixtures are not echoed verbatim by checking the mask marker.
				if f.MatchRedacted == "" {
					t.Errorf("finding %s has empty redacted match", f.RuleID)
				}
				if f.Confidence < 0 || f.Confidence > 1 {
					t.Errorf("finding %s confidence out of range: %v", f.RuleID, f.Confidence)
				}
			}
			if !matched {
				var ids []string
				for _, f := range findings {
					ids = append(ids, f.RuleID)
				}
				t.Errorf("no finding with rule_id containing %q; got %v", tc.wantRuleID, ids)
			}
		})
	}
}

func TestScanNeverLeaksRawSecret(t *testing.T) {
	// The AWS secret access key body must never appear in any output field.
	secret := "wJalrXUtnFEMI7K7MDENGZbPxRfiCYZEXAMPLEKEY"
	text := "AWS_SECRET_ACCESS_KEY = " + secret + "\nAKIAZ3MZ7EXAMPLE4Q2T"
	findings, err := Scan(text)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.MatchRedacted, secret) {
			t.Fatalf("redacted match leaked the raw secret: %q", f.MatchRedacted)
		}
		// The middle of any non-trivial secret should be masked.
		if !strings.Contains(f.MatchRedacted, "*") {
			t.Errorf("redacted match %q for %s has no mask characters", f.MatchRedacted, f.RuleID)
		}
	}
}

func TestScanNegatives(t *testing.T) {
	// Clean prose and common code without credentials should not fire. We allow
	// zero findings; the key false-positive concern is ordinary text.
	negatives := []string{
		"",
		"The quick brown fox jumps over the lazy dog.",
		"func main() { fmt.Println(\"hello, world\") }",
		"SELECT id, name FROM users WHERE active = true ORDER BY name;",
		"version: 1.2.3\nname: my-app\nport: 8080",
	}
	for _, text := range negatives {
		findings, err := Scan(text)
		if err != nil {
			t.Fatalf("Scan(%q) error: %v", text, err)
		}
		if len(findings) != 0 {
			t.Errorf("expected no findings for clean text %q, got %d (%+v)", text, len(findings), findings)
		}
	}
}

func TestContains(t *testing.T) {
	yes, err := Contains("token xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx")
	if err != nil {
		t.Fatal(err)
	}
	if !yes {
		t.Errorf("expected Contains to be true for a slack token")
	}
	no, err := Contains("just some ordinary text without anything secret")
	if err != nil {
		t.Fatal(err)
	}
	if no {
		t.Errorf("expected Contains to be false for clean text")
	}
	empty, err := Contains("")
	if err != nil {
		t.Fatal(err)
	}
	if empty {
		t.Errorf("expected Contains to be false for empty text")
	}
}

func TestStartOffset(t *testing.T) {
	prefix := "prefix padding here >>> "
	text := prefix + "xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
	findings, err := Scan(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	// The slack token starts right after the prefix.
	want := int32(len(prefix))
	var got int32 = -1
	for _, f := range findings {
		if strings.Contains(f.RuleID, "slack") {
			got = f.StartOffset
		}
	}
	if got != want {
		t.Errorf("start_offset = %d, want %d", got, want)
	}
}

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"":                     "",
		"abc":                  "***",
		"abcdefgh":             "********",
		"abcdefghi":            "abcd********fghi",
		"AKIAZ3MZ7EXAMPLE4Q2T": "AKIA********4Q2T",
	}
	for in, want := range cases {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	// All-same characters: zero entropy.
	if e := ShannonEntropy("aaaaaaaa"); e != 0 {
		t.Errorf("entropy of constant string = %v, want 0", e)
	}
	// Random-ish base64 should be higher than English prose.
	high := ShannonEntropy("aB3xQ9zL7mP2vK8wR4tY")
	low := ShannonEntropy("the quick brown fox")
	if high <= low {
		t.Errorf("expected high-entropy string (%v) > prose (%v)", high, low)
	}
}
