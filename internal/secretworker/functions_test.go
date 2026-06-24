// Copyright 2026 Query Farm LLC - https://query.farm

package secretworker

import (
	"bytes"
	"context"
	"encoding/gob"
	"testing"

	"github.com/Query-farm/vgi-go/vgi"
	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/memory"
)

// TestRegisterDoesNotPanic exercises the SDK registration path. vgi-go PANICS
// at RegisterTable if a table-function state struct holds non-gob-encodable
// fields (the gob-state gotcha); a clean Register here proves secretScanState is
// gob-safe.
func TestRegisterDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Register panicked: %v", r)
		}
	}()
	w := vgi.NewWorker(vgi.WithCatalogName(CatalogName))
	Register(w)
}

// TestCursorSurvivesContinuation proves the streaming cursor round-trips through
// a gob snapshot between Process ticks — the exact path the stateless HTTP
// transport takes when it resumes a producer from its continuation token. A
// multi-row producer that advances Offset BEFORE yielding emits each finding
// exactly once and terminates (the bug a bare Done flag re-emitted forever over
// HTTP).
func TestCursorSurvivesContinuation(t *testing.T) {
	const total = 1000 // > rowsPerTick (256), so it spans several continuations
	rows := make([]Finding, total)
	for i := range rows {
		rows[i] = Finding{RuleID: "aws-access-token", StartOffset: int32(i)}
	}
	st := &secretScanState{Cursor{Rows: rows}}

	emitted := 0
	for tick := 0; tick < total+5; tick++ {
		slice, done := st.nextSlice()
		if done {
			break
		}
		emitted += len(slice)
		// Simulate the HTTP continuation boundary: gob-encode then decode the
		// LIVE state, and resume from the snapshot (never the in-memory state).
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(st); err != nil {
			t.Fatalf("gob encode: %v", err)
		}
		var resumed secretScanState
		if err := gob.NewDecoder(&buf).Decode(&resumed); err != nil {
			t.Fatalf("gob decode: %v", err)
		}
		st = &resumed
	}
	if emitted != total {
		t.Fatalf("cursor emitted %d rows across continuations, want %d", emitted, total)
	}
	if _, done := st.nextSlice(); !done {
		t.Fatal("cursor did not report done after draining all rows")
	}
}

// buildStringBatch wraps a single VARCHAR value as a 1-row Arrow batch suitable
// for a scalar Process call.
func buildStringBatch(t *testing.T, val string, null bool) (arrow.RecordBatch, *vgi.ProcessParams) {
	t.Helper()
	schema := arrow.NewSchema([]arrow.Field{{Name: "text", Type: arrow.BinaryTypes.String, Nullable: true}}, nil)
	b := array.NewStringBuilder(memory.NewGoAllocator())
	defer b.Release()
	if null {
		b.AppendNull()
	} else {
		b.Append(val)
	}
	arr := b.NewArray()
	defer arr.Release()
	batch := array.NewRecordBatch(schema, []arrow.Array{arr}, 1)
	outSchema := arrow.NewSchema([]arrow.Field{{Name: "result", Type: arrow.FixedWidthTypes.Boolean}}, nil)
	return batch, &vgi.ProcessParams{OutputSchema: outSchema}
}

func TestSecretContainsProcess(t *testing.T) {
	f := &SecretContainsFunction{}

	// Positive: a slack token present.
	batch, params := buildStringBatch(t, "xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx", false)
	defer batch.Release()
	out, err := f.Process(context.Background(), params, batch)
	if err != nil {
		t.Fatalf("Process error: %v", err)
	}
	col := out.Column(0).(*array.Boolean)
	if !col.Value(0) {
		t.Errorf("expected secret_contains=true for a slack token")
	}

	// Negative: clean text.
	batch2, params2 := buildStringBatch(t, "nothing secret here at all", false)
	defer batch2.Release()
	out2, err := f.Process(context.Background(), params2, batch2)
	if err != nil {
		t.Fatalf("Process error: %v", err)
	}
	if out2.Column(0).(*array.Boolean).Value(0) {
		t.Errorf("expected secret_contains=false for clean text")
	}

	// NULL input -> false (not an error).
	batch3, params3 := buildStringBatch(t, "", true)
	defer batch3.Release()
	out3, err := f.Process(context.Background(), params3, batch3)
	if err != nil {
		t.Fatalf("Process error on NULL: %v", err)
	}
	if out3.Column(0).(*array.Boolean).Value(0) {
		t.Errorf("expected secret_contains=false for NULL input")
	}
}
