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
// stores plain exported Finding slices plus a Done flag, fetched eagerly in
// NewState, and rebuilds the Arrow batch in Process.

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
// has only exported scalar fields) plus the emit flag.
type secretScanState struct {
	Done     bool
	Findings []Finding
}

// SecretScanFunction emits one row per secret finding in the input text.
type SecretScanFunction struct{}

func (f *SecretScanFunction) Name() string { return "secret_scan" }

func (f *SecretScanFunction) Metadata() vgi.FunctionMetadata {
	return vgi.FunctionMetadata{
		Description: "Scan text/code for leaked secrets; emit one row per finding (rule_id, description, match_redacted, start_offset, entropy, confidence). Redacted output only; no verification.",
		Stability:   vgi.StabilityConsistent,
		Categories:  []string{"secretscan", "security", "secrets"},
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
	return &secretScanState{Findings: findings}, nil
}

func (f *SecretScanFunction) Process(_ context.Context, _ *vgi.ProcessParams, state *secretScanState, out *vgirpc.OutputCollector) error {
	if state.Done {
		return out.Finish()
	}
	state.Done = true

	r := state.Findings
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
