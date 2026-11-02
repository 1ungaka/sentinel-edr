package quarantine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeSample drops a file with content and mode under dir and returns its path.
func writeSample(t *testing.T, dir, name string, content []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, content, mode); err != nil {
		t.Fatalf("write sample: %v", err)
	}
	return p
}

func TestQuarantineMovesAndNeutralizes(t *testing.T) {
	work := t.TempDir()
	// A fake PE header so we can assert the vault does not keep it runnable.
	content := append([]byte("MZ\x90\x00"), bytes.Repeat([]byte("payload"), 100)...)
	src := writeSample(t, work, "evil.exe", content, 0o755)

	s, err := Open(filepath.Join(work, "vault"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	e, err := s.Quarantine(src, "Win.Trojan.Test", false)
	if err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	// Original is gone (moved, not copied).
	if _, err := os.Stat(src); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("original still present after move: %v", err)
	}
	// Recorded metadata is faithful.
	if e.Size != int64(len(content)) {
		t.Errorf("size = %d, want %d", e.Size, len(content))
	}
	if e.Mode != 0o755 {
		t.Errorf("mode = %o, want 0755", e.Mode)
	}
	want := sha256.Sum256(content)
	if e.SHA256 != hex.EncodeToString(want[:]) {
		t.Errorf("sha256 mismatch")
	}

	// The stored blob must NOT be the original bytes (neutralized at rest) and
	// must not start with the MZ magic.
	blob, err := os.ReadFile(s.blobPath(e.ID))
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	if bytes.Equal(blob, content) {
		t.Error("blob stored verbatim; expected XOR mask")
	}
	if bytes.HasPrefix(blob, []byte("MZ")) {
		t.Error("blob retains MZ magic; not neutralized")
	}
}

func TestQuarantineKeepOriginal(t *testing.T) {
	work := t.TempDir()
	src := writeSample(t, work, "keep.bin", []byte("abc"), 0o644)
	s, _ := Open(filepath.Join(work, "vault"))
	if _, err := s.Quarantine(src, "manual", true); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if _, err := os.Stat(src); err != nil {
		t.Errorf("original removed despite keepOriginal: %v", err)
	}
}

func TestRestoreRoundTrip(t *testing.T) {
	work := t.TempDir()
	content := bytes.Repeat([]byte{0x00, 0xff, 0x41, 0x7f}, 64)
	src := writeSample(t, work, "data.dat", content, 0o640)
	s, _ := Open(filepath.Join(work, "vault"))
	e, err := s.Quarantine(src, "test", false)
	if err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	dest := filepath.Join(work, "restored.dat")
	got, err := s.Restore(e.ID, dest, false)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got != dest {
		t.Errorf("restore path = %q, want %q", got, dest)
	}
	back, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(back, content) {
		t.Error("restored bytes differ from original")
	}
	info, _ := os.Stat(dest)
	if info.Mode().Perm() != 0o640 {
		t.Errorf("restored mode = %o, want 0640", info.Mode().Perm())
	}
}

func TestRestoreToOriginalPath(t *testing.T) {
	work := t.TempDir()
	src := writeSample(t, work, "orig.bin", []byte("hello world"), 0o644)
	s, _ := Open(filepath.Join(work, "vault"))
	e, _ := s.Quarantine(src, "test", false)

	// Empty dest => OriginalPath.
	got, err := s.Restore(e.ID, "", false)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got != e.OriginalPath {
		t.Errorf("restore path = %q, want original %q", got, e.OriginalPath)
	}
}

func TestRestoreRefusesExistingDest(t *testing.T) {
	work := t.TempDir()
	src := writeSample(t, work, "a.bin", []byte("xyz"), 0o644)
	s, _ := Open(filepath.Join(work, "vault"))
	e, _ := s.Quarantine(src, "test", false)

	dest := writeSample(t, work, "occupied.bin", []byte("do not clobber"), 0o644)
	if _, err := s.Restore(e.ID, dest, false); !errors.Is(err, ErrExists) {
		t.Fatalf("restore over existing file: err = %v, want ErrExists", err)
	}
	// The existing file is untouched.
	if b, _ := os.ReadFile(dest); string(b) != "do not clobber" {
		t.Error("destination was modified despite ErrExists")
	}
	// overwrite=true proceeds.
	if _, err := s.Restore(e.ID, dest, true); err != nil {
		t.Fatalf("restore with overwrite: %v", err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "xyz" {
		t.Error("overwrite restore did not write original bytes")
	}
}

func TestIntegrityFailsOnTamper(t *testing.T) {
	work := t.TempDir()
	src := writeSample(t, work, "a.bin", bytes.Repeat([]byte("Z"), 50), 0o644)
	s, _ := Open(filepath.Join(work, "vault"))
	e, _ := s.Quarantine(src, "test", false)

	// Corrupt the stored blob.
	blobPath := s.blobPath(e.ID)
	blob, _ := os.ReadFile(blobPath)
	blob[0] ^= 0xff
	if err := os.WriteFile(blobPath, blob, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := s.Verify(e.ID); !errors.Is(err, ErrIntegrity) {
		t.Errorf("Verify after tamper: err = %v, want ErrIntegrity", err)
	}
	if _, err := s.Restore(e.ID, filepath.Join(work, "out.bin"), false); !errors.Is(err, ErrIntegrity) {
		t.Errorf("Restore after tamper: err = %v, want ErrIntegrity", err)
	}
	// A failed restore writes nothing.
	if _, err := os.Stat(filepath.Join(work, "out.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Error("restore wrote a file despite integrity failure")
	}
}

func TestIntegrityFailsOnMissingBlob(t *testing.T) {
	work := t.TempDir()
	src := writeSample(t, work, "a.bin", []byte("data"), 0o644)
	s, _ := Open(filepath.Join(work, "vault"))
	e, _ := s.Quarantine(src, "test", false)
	if err := os.Remove(s.blobPath(e.ID)); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(e.ID); !errors.Is(err, ErrIntegrity) {
		t.Errorf("Verify with missing blob: err = %v, want ErrIntegrity", err)
	}
}

func TestVerifyAll(t *testing.T) {
	work := t.TempDir()
	s, _ := Open(filepath.Join(work, "vault"))
	var ids []string
	for _, n := range []string{"a", "b", "c"} {
		src := writeSample(t, work, n+".bin", []byte("content-"+n), 0o644)
		e, _ := s.Quarantine(src, "test", false)
		ids = append(ids, e.ID)
	}
	failed, err := s.VerifyAll()
	if err != nil {
		t.Fatalf("VerifyAll: %v", err)
	}
	if len(failed) != 0 {
		t.Errorf("intact vault reported failures: %v", failed)
	}
	// Corrupt the middle one.
	blob, _ := os.ReadFile(s.blobPath(ids[1]))
	blob[0] ^= 0xff
	os.WriteFile(s.blobPath(ids[1]), blob, 0o600)

	failed, err = s.VerifyAll()
	if err != nil {
		t.Fatalf("VerifyAll: %v", err)
	}
	if len(failed) != 1 || failed[0] != ids[1] {
		t.Errorf("VerifyAll failed = %v, want [%s]", failed, ids[1])
	}
}

func TestListNewestFirst(t *testing.T) {
	work := t.TempDir()
	s, _ := Open(filepath.Join(work, "vault"))
	var last string
	for _, n := range []string{"first", "second", "third"} {
		src := writeSample(t, work, n+".bin", []byte(n), 0o644)
		e, _ := s.Quarantine(src, "test", false)
		last = e.ID
	}
	list, err := s.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("list len = %d, want 3", len(list))
	}
	if list[0].ID != last {
		t.Errorf("newest-first ordering broken: head = %s, want %s", list[0].ID, last)
	}
}

func TestDelete(t *testing.T) {
	work := t.TempDir()
	src := writeSample(t, work, "a.bin", []byte("gone"), 0o644)
	s, _ := Open(filepath.Join(work, "vault"))
	e, _ := s.Quarantine(src, "test", false)

	if err := s.Delete(e.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := os.Stat(s.blobPath(e.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Error("blob survived delete")
	}
	if _, err := s.Get(e.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after delete: err = %v, want ErrNotFound", err)
	}
	if err := s.Delete("deadbeef"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete missing: err = %v, want ErrNotFound", err)
	}
}

func TestReopenPersistsIndex(t *testing.T) {
	work := t.TempDir()
	vault := filepath.Join(work, "vault")
	src := writeSample(t, work, "a.bin", []byte("persist"), 0o644)

	s1, _ := Open(vault)
	e, _ := s1.Quarantine(src, "test", false)

	s2, err := Open(vault)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err := s2.Get(e.ID)
	if err != nil {
		t.Fatalf("get after reopen: %v", err)
	}
	if got.OriginalPath != e.OriginalPath {
		t.Error("entry did not persist across reopen")
	}
}

func TestGetNotFound(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "vault"))
	if _, err := s.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestOpenRejectsBadIndexVersion(t *testing.T) {
	work := t.TempDir()
	vault := filepath.Join(work, "vault")
	if _, err := Open(vault); err != nil {
		t.Fatal(err)
	}
	// Rewrite the index with a future version.
	bad, _ := json.Marshal(index{Version: 99})
	if err := os.WriteFile(filepath.Join(vault, indexName), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(vault); err == nil {
		t.Error("Open accepted an incompatible index version")
	}
}

func TestQuarantineRejectsNonRegular(t *testing.T) {
	work := t.TempDir()
	s, _ := Open(filepath.Join(work, "vault"))
	if _, err := s.Quarantine(work, "test", false); err == nil {
		t.Error("quarantined a directory; expected an error")
	}
}

func TestXorMaskIsInvolution(t *testing.T) {
	data := []byte("the quick brown fox")
	key := []byte("k3y")
	if got := xorMask(xorMask(data, key), key); !bytes.Equal(got, data) {
		t.Error("xorMask is not its own inverse")
	}
}
