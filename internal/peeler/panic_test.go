package peeler

import (
	"bytes"
	"context"
	"testing"
)

// layerOne hands the root blob to a second unwrapper on a spawned goroutine,
// which is where the panic has to be survived.
type layerOne struct{}

func (layerOne) Name() string                                 { return "layer-one" }
func (layerOne) Detect(b []byte) bool                         { return bytes.HasPrefix(b, []byte("root")) }
func (layerOne) Unwrap(b []byte, limit int64) ([]byte, error) { return []byte("child-layer"), nil }

type detonator struct{}

func (detonator) Name() string { return "detonator" }
func (detonator) Detect(b []byte) bool {
	if bytes.HasPrefix(b, []byte("child")) {
		panic("hostile input reached a broken decoder")
	}
	return false
}
func (detonator) Unwrap(b []byte, limit int64) ([]byte, error) { return nil, ErrNotThisLayer }

// The engine's recover only covers the goroutine ScanFile runs on. A panic on a
// goroutine the peeler spawned cannot reach it, and an unrecovered goroutine
// panic ends the process: every other file's result, and the daemon with them.
func TestPanicInASpawnedLayerDoesNotEscape(t *testing.T) {
	p := New(WithUnwrappers([]Unwrapper{layerOne{}, detonator{}}), WithParallelism(4))
	r := p.Peel(context.Background(), []byte("root-blob"))
	if !r.Exhausted {
		t.Fatalf("a recovered panic must mark the peel incomplete, got %+v", r)
	}
}

func TestPanicAtTheRootDoesNotEscape(t *testing.T) {
	p := New(WithUnwrappers([]Unwrapper{detonator{}}))
	if r := p.Peel(context.Background(), []byte("child-at-root")); !r.Exhausted {
		t.Fatalf("a recovered panic must mark the peel incomplete, got %+v", r)
	}
}
