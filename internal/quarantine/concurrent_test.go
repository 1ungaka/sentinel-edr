package quarantine

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

// The daemon and an operator's `cau quarantine` are separate processes sharing a
// vault. Each entry holds the only key to its blob and the original is deleted
// once it is stored, so an index update lost to a read-modify-write race is
// unrecoverable data.
func TestConcurrentQuarantinesKeepEveryEntry(t *testing.T) {
	src, vault := t.TempDir(), t.TempDir()
	const n = 24
	paths := make([]string, n)
	for i := range paths {
		paths[i] = writeSample(t, src, fmt.Sprintf("s%d", i), []byte(fmt.Sprintf("sample %d", i)), 0o644)
	}

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for _, p := range paths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			// A Store each, as separate processes would have.
			s, err := Open(vault)
			if err != nil {
				errs <- err
				return
			}
			if _, err := s.Quarantine(p, "test", false); err != nil {
				errs <- err
			}
		}(p)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	s, err := Open(vault)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != n {
		t.Fatalf("index holds %d of %d entries: the rest are unrecoverable", len(entries), n)
	}
	if blobs, _ := filepath.Glob(filepath.Join(vault, blobSubdir, "*")); len(blobs) != n {
		t.Fatalf("%d blobs on disk, want %d", len(blobs), n)
	}
}
