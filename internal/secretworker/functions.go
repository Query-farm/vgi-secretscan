// Copyright 2026 Query Farm LLC - https://query.farm

package secretworker

import (
	"context"

	"github.com/Query-farm/vgi-go/vgi"
	"github.com/Query-farm/vgi-rpc-go/vgirpc"
	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
)

// Compile-time checks: the scalar implements vgi.ScalarFunction directly (no
// typed wrapper needed) and the table function the typed interface.
var (
	_ vgi.ScalarFunction                  = (*SecretContainsFunction)(nil)
	_ vgi.TypedTableFunc[secretScanState] = (*SecretScanFunction)(nil)
)

// IMPORTANT (gob-state gotcha): table-function state is gob-encoded by the SDK
// between NewState and Process (it may cross a process boundary over HTTP). The
// state struct must hold only EXPORTED, gob-encodable fields — no arrow.Record,
// interfaces, channels, funcs, or unexported fields. secretScanState therefore
// stores plain exported Finding slices in an embedded Cursor, computed eagerly
// in NewState, and rebuilds the Arrow batch in Process.
//
// WHY AN EXPLICIT CURSOR, NOT A bool Done (the HTTP-continuation fix):
//
// Over the stateless HTTP transport the worker keeps NO live state between
// Process ticks — the framework round-trips the producer state through an opaque
// continuation token: after each tick it gob-encodes the LIVE user state, the
// client returns the token, and the worker resumes by gob-decoding it. The HTTP
// server emits at most one data batch per response, so a producer with more to
// emit is always resumed mid-stream from its token. A bare `Done bool` flipped
// *after* the single Emit observes the pre-Emit snapshot on resume, re-emits the
// same rows forever, and pins the worker in an infinite loop (subprocess/unix
// hold live state in memory, so they never hit it). secret_scan emits one row
// per finding (a blob can hold many), so this is mandatory. The fix: the state
// embeds Cursor carrying the Findings plus the Offset of the next unemitted row;
// Process emits a bounded slice from Offset, advances Offset BEFORE yielding, and
// Finish()es once Offset >= len(Rows). The framework snapshots Offset into the
// token, so HTTP resumes correctly and terminates.

// rowsPerTick bounds how many rows each Process tick emits. Emitting a bounded
// slice and advancing the cursor is what makes the offset observable across the
// HTTP continuation boundary (and scales to many findings).
const rowsPerTick = 256

// Cursor is the streaming cursor embedded by the table-function state: the
// eagerly computed findings plus the offset of the next unemitted row. Both
// fields are exported so gob round-trips them through the HTTP continuation
// token. The TYPE is exported (Cursor, not cursor) because the SDK counts a
// state struct's exported FIELDS at registration to verify it is gob-encodable.
type Cursor struct {
	Rows   []Finding
	Offset int
}

// nextSlice returns the next bounded slice of findings to emit and advances the
// cursor past them. It reports done=true once all findings have been consumed,
// at which point Process should call out.Finish().
func (c *Cursor) nextSlice() (slice []Finding, done bool) {
	if c.Offset >= len(c.Rows) {
		return nil, true
	}
	end := c.Offset + rowsPerTick
	if end > len(c.Rows) {
		end = len(c.Rows)
	}
	slice = c.Rows[c.Offset:end]
	c.Offset = end
	return slice, false
}

// ===========================================================================
// scalar: secret_contains(text VARCHAR) -> BOOLEAN
// ===========================================================================

// SecretContainsFunction reports whether a text value contains any detectable
// secret. It is the cheap predicate for filtering (e.g. in a WHERE clause); use
// secret_scan() to see the individual findings.
type SecretContainsFunction struct{}

func (f *SecretContainsFunction) Name() string { return "secret_contains" }

func (f *SecretContainsFunction) Metadata() vgi.FunctionMetadata {
	return vgi.FunctionMetadata{
		Description: "Report whether a text/code value contains at least one detectable leaked secret (gitleaks ruleset + entropy). Offline; no verification.",
		Stability:   vgi.StabilityConsistent,
		ReturnType:  arrow.FixedWidthTypes.Boolean,
		Categories:  []string{"secretscan", "security", "secrets"},
		Examples: []vgi.CatalogExample{
			{
				SQL:         "SELECT secretscan.main.secret_contains('aws_secret = AKIAZ3MZ7EXAMPLE4Q2T') AS leaked;",
				Description: "Check whether a single string holds any detectable secret (returns TRUE here for the AWS-style key).",
			},
			{
				SQL:         "SELECT path FROM source_files WHERE secretscan.main.secret_contains(contents);",
				Description: "Filter a table of files down to those whose contents contain at least one leaked secret.",
			},
		},
	}
}

func (f *SecretContainsFunction) ArgumentSpecs() []vgi.ArgSpec {
	return []vgi.ArgSpec{
		{Name: "text", Position: 0, ArrowType: "varchar", Doc: "Text or source code to scan"},
	}
}

func (f *SecretContainsFunction) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindResult(arrow.FixedWidthTypes.Boolean)
}

func (f *SecretContainsFunction) Process(_ context.Context, params *vgi.ProcessParams, batch arrow.RecordBatch) (arrow.RecordBatch, error) {
	var firstErr error
	out, mapErr := vgi.MapColumn(params, batch, 0, array.NewBooleanBuilder,
		func(col arrow.Array, i int) bool {
			if col.IsNull(i) {
				return false
			}
			ok, err := Contains(vgi.GetStringValue(col, i))
			if err != nil && firstErr == nil {
				firstErr = err
			}
			return ok
		})
	if firstErr != nil {
		return nil, firstErr
	}
	return out, mapErr
}

// NewSecretContainsFunction builds the registerable scalar function.
func NewSecretContainsFunction() vgi.ScalarFunction { return &SecretContainsFunction{} }

// ===========================================================================
// table: secret_scan(text) -> one row per finding
// ===========================================================================

// secretScanSchema is the output schema. The match column is ALWAYS the
// redacted match — the raw secret never appears.
var secretScanSchema = arrow.NewSchema([]arrow.Field{
	{Name: "rule_id", Type: arrow.BinaryTypes.String},
	{Name: "description", Type: arrow.BinaryTypes.String},
	{Name: "match_redacted", Type: arrow.BinaryTypes.String},
	{Name: "start_offset", Type: arrow.PrimitiveTypes.Int32},
	{Name: "entropy", Type: arrow.PrimitiveTypes.Float64},
	{Name: "confidence", Type: arrow.PrimitiveTypes.Float64},
}, nil)

type secretScanArgs struct {
	Text string `vgi:"pos=0,doc=Text or source code to scan (VARCHAR constant)"`
}

// secretScanState holds the eagerly-computed findings (gob-encodable: Finding
// has only exported scalar fields) in an embedded streaming cursor.
type secretScanState struct {
	Cursor
}

// SecretScanFunction emits one row per secret finding in the input text.
type SecretScanFunction struct{}

func (f *SecretScanFunction) Name() string { return "secret_scan" }

func (f *SecretScanFunction) Metadata() vgi.FunctionMetadata {
	return vgi.FunctionMetadata{
		Description: "Scan text/code for leaked secrets; emit one row per finding (rule_id, description, match_redacted, start_offset, entropy, confidence). Redacted output only; no verification.",
		Stability:   vgi.StabilityConsistent,
		Categories:  []string{"secretscan", "security", "secrets"},
		Tags: map[string]string{
			"vgi.columns_md": "| Column | Type | Description |\n" +
				"| --- | --- | --- |\n" +
				"| `rule_id` | VARCHAR | Identifier of the gitleaks rule that matched (e.g. `aws-access-token`, `private-key`, `generic-api-key`). |\n" +
				"| `description` | VARCHAR | Human-readable description of the matched rule. |\n" +
				"| `match_redacted` | VARCHAR | The matched text with the secret substring masked — the raw credential is never returned. |\n" +
				"| `start_offset` | INTEGER | Zero-based byte offset of the match within the input text. |\n" +
				"| `entropy` | DOUBLE | Shannon entropy of the detected secret (gitleaks value, or a computed fallback when the rule has no entropy threshold). |\n" +
				"| `confidence` | DOUBLE | Heuristic confidence score in [0,1]: structurally distinctive rules (AWS/GCP/GitHub/private-key/JWT) score high; generic/entropy rules scale with entropy. |",
		},
		Examples: []vgi.CatalogExample{
			{
				SQL:         "SELECT rule_id, match_redacted, confidence FROM secretscan.main.secret_scan('aws_secret = AKIAZ3MZ7EXAMPLE4Q2T');",
				Description: "List each secret found in a string, with its rule, redacted match, and confidence.",
			},
			{
				SQL:         "SELECT f.path, s.rule_id, s.start_offset FROM source_files f, secretscan.main.secret_scan(f.contents) s WHERE s.confidence >= 0.9;",
				Description: "Join a files table with secret_scan to report high-confidence leaks per file, including their byte offset.",
			},
		},
	}
}

func (f *SecretScanFunction) ArgumentSpecs() []vgi.ArgSpec {
	return vgi.DeriveArgSpecs(secretScanArgs{})
}

func (f *SecretScanFunction) OnBind(_ *vgi.BindParams) (*vgi.BindResponse, error) {
	return vgi.BindSchema(secretScanSchema)
}

func (f *SecretScanFunction) NewState(params *vgi.ProcessParams) (*secretScanState, error) {
	var args secretScanArgs
	if err := vgi.BindArgs(params.Args, &args); err != nil {
		return nil, err
	}
	// A NULL text yields zero rows (not an error), mirroring vgi-ioc.
	if isNullArg(params.Args, 0) {
		return &secretScanState{}, nil
	}
	findings, err := Scan(args.Text)
	if err != nil {
		return nil, err
	}
	return &secretScanState{Cursor{Rows: findings}}, nil
}

func (f *SecretScanFunction) Process(_ context.Context, _ *vgi.ProcessParams, state *secretScanState, out *vgirpc.OutputCollector) error {
	r, done := state.nextSlice()
	if done {
		return out.Finish()
	}
	n := int64(len(r))
	batch := array.NewRecordBatch(secretScanSchema, []arrow.Array{
		vgi.BuildStringArray(n, func(i int64) string { return r[i].RuleID }),
		vgi.BuildStringArray(n, func(i int64) string { return r[i].Description }),
		vgi.BuildStringArray(n, func(i int64) string { return r[i].MatchRedacted }),
		vgi.BuildInt32Array(n, func(i int64) int32 { return r[i].StartOffset }),
		vgi.BuildFloat64Array(n, func(i int64) float64 { return r[i].Entropy }),
		vgi.BuildFloat64Array(n, func(i int64) float64 { return r[i].Confidence }),
	}, n)
	defer batch.Release()
	return out.Emit(batch)
}

// NewSecretScanFunction builds the registerable table function.
func NewSecretScanFunction() vgi.TableFunction {
	return vgi.AsTableFunction[secretScanState](&SecretScanFunction{})
}

// ===========================================================================
// helpers + registration
// ===========================================================================

// isNullArg reports whether positional argument pos is present and NULL.
func isNullArg(args *vgi.Arguments, pos int) bool {
	if args == nil {
		return true
	}
	col, err := args.GetColumn(pos)
	if err != nil {
		return false
	}
	return col.Len() == 0 || col.IsNull(0)
}

// Register registers the secret-scan scalar + table functions on the worker.
func Register(w *vgi.Worker) {
	w.RegisterScalar(NewSecretContainsFunction())
	w.RegisterTable(NewSecretScanFunction())
}
