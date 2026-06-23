// Copyright 2026 Query Farm LLC - https://query.farm

// Package secretworker implements the vgi-secretscan VGI worker: scalar and
// table functions that scan free text / source code for leaked secrets
// (cloud keys, tokens, private keys, JWTs, high-entropy strings) using the
// embedded gitleaks detection engine plus Shannon-entropy heuristics.
//
// Detection is pure and fully offline — no network, and crucially NO
// verification (the worker never tests whether a found credential is live;
// see README "Out of scope"). Output is always the REDACTED match: the raw
// secret value never leaves this process.
package secretworker

import (
	"math"
	"sort"
	"strings"
	"sync"

	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

// CatalogName is the VGI catalog name advertised by this worker.
const CatalogName = "secretscan"

// Finding is a single, redaction-safe secret detection. It deliberately does
// NOT carry the raw secret — only a redacted form — so a Finding can be emitted
// to a caller without leaking the credential.
type Finding struct {
	RuleID        string  // gitleaks rule id, e.g. "aws-access-token"
	Description   string  // human-readable rule description
	MatchRedacted string  // the matched text with the secret portion masked
	StartOffset   int32   // 0-based byte offset of the match within the input
	Entropy       float64 // Shannon entropy of the secret value (bits/char)
	Confidence    float64 // 0..1 heuristic confidence (see scoreConfidence)
}

// detector lazily builds the gitleaks detector from its embedded default
// ruleset exactly once. NewDetectorDefaultConfig parses the embedded
// gitleaks.toml (the upstream MIT ruleset) via viper; doing it once avoids
// re-parsing for every batch and keeps viper's global state untouched after
// startup.
var (
	detOnce sync.Once
	det     *detect.Detector
	detErr  error
)

func sharedDetector() (*detect.Detector, error) {
	detOnce.Do(func() {
		det, detErr = detect.NewDetectorDefaultConfig()
		if det != nil {
			// We scan in-memory strings, never files; disable the file-size
			// guard so a large pasted blob is still scanned in full.
			det.MaxTargetMegaBytes = 0
		}
	})
	return det, detErr
}

// Scan returns every secret finding in text, redacted and sorted by start
// offset. Empty text yields no findings. It never returns the raw secret.
func Scan(text string) ([]Finding, error) {
	if text == "" {
		return nil, nil
	}
	d, err := sharedDetector()
	if err != nil {
		return nil, err
	}

	raw := d.DetectString(text)
	out := make([]Finding, 0, len(raw))
	for _, f := range raw {
		entropy := float64(f.Entropy)
		// gitleaks does not compute entropy for every rule (only those with an
		// entropy threshold). Fall back to our own Shannon entropy of the
		// secret so callers always get a usable number to threshold on.
		if entropy == 0 && f.Secret != "" {
			entropy = ShannonEntropy(f.Secret)
		}
		out = append(out, Finding{
			RuleID:        f.RuleID,
			Description:   f.Description,
			MatchRedacted: redactMatch(f.Match, f.Secret),
			StartOffset:   offsetOf(text, f),
			Entropy:       entropy,
			Confidence:    scoreConfidence(f.RuleID, entropy),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].StartOffset != out[j].StartOffset {
			return out[i].StartOffset < out[j].StartOffset
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out, nil
}

// Contains reports whether text contains at least one secret finding.
func Contains(text string) (bool, error) {
	if text == "" {
		return false, nil
	}
	d, err := sharedDetector()
	if err != nil {
		return false, err
	}
	return len(d.DetectString(text)) > 0, nil
}

// offsetOf returns the 0-based byte offset of a finding's match within text.
// gitleaks reports StartLine/StartColumn (1-based, per line); we recompute the
// absolute offset by locating the match. The Match string contains the secret,
// so searching from the reported line start is both correct and avoids the
// off-by-one ambiguities of column arithmetic across multibyte runes.
func offsetOf(text string, f report.Finding) int32 {
	// Prefer an exact search for the matched substring.
	needle := f.Match
	if needle == "" {
		needle = f.Secret
	}
	if needle == "" {
		return 0
	}
	if idx := strings.Index(text, needle); idx >= 0 {
		return int32(idx)
	}
	return 0
}

// redactMatch masks the secret portion inside the matched text, preserving any
// surrounding context (e.g. an assignment prefix) so a caller can see WHERE the
// secret was without seeing WHAT it was. A short secret is fully masked; a
// longer one keeps a 4-char prefix and suffix so distinct leaks remain
// distinguishable without being reconstructable.
func redactMatch(match, secret string) string {
	if secret == "" {
		// Some rules have no distinct secret group; redact the whole match.
		return Redact(match)
	}
	red := Redact(secret)
	if strings.Contains(match, secret) {
		return strings.Replace(match, secret, red, 1)
	}
	// Defensive: the secret should be a substring of the match, but if a rule
	// transforms it (e.g. decoding), fall back to redacting the whole match.
	return Redact(match)
}

// Redact masks a secret value: <=8 chars become all asterisks; longer values
// keep the first and last 4 characters with the middle masked. The mask length
// is fixed (not proportional) so the redaction never reveals the exact length
// of a long secret.
func Redact(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + "********" + s[len(s)-4:]
}

// ShannonEntropy returns the Shannon entropy (bits per character) of s. It is
// the standard high-entropy heuristic: random/encoded secrets score high
// (~4-6), English prose scores low (~2.5-4).
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// scoreConfidence maps a rule id and entropy to a 0..1 confidence. Rules that
// match a structurally distinctive token (a fixed prefix like "AKIA", "ghp_",
// "xox", a PEM header) are high-precision and score high regardless of
// entropy. The catch-all "generic-api-key" / entropy rules are noisier, so
// their confidence scales with entropy. This lets callers threshold:
//
//	WHERE confidence >= 0.8   -- only structurally-certain leaks
func scoreConfidence(ruleID string, entropy float64) float64 {
	id := strings.ToLower(ruleID)
	switch {
	case strings.Contains(id, "generic") || strings.Contains(id, "entropy"):
		// Noisy: scale entropy in [3.0, 5.0] -> [0.3, 0.75].
		return clamp(0.3+(entropy-3.0)*0.225, 0.3, 0.75)
	case strings.Contains(id, "private-key") ||
		strings.Contains(id, "aws") ||
		strings.Contains(id, "gcp") ||
		strings.Contains(id, "azure") ||
		strings.Contains(id, "github") ||
		strings.Contains(id, "gitlab") ||
		strings.Contains(id, "slack") ||
		strings.Contains(id, "stripe") ||
		strings.Contains(id, "jwt"):
		// Structurally distinctive, high-precision rules.
		return 0.95
	default:
		// Other named provider rules: solidly trustworthy, a notch below the
		// marquee providers.
		return 0.85
	}
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
