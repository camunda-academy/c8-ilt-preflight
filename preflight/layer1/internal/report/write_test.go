package report

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"c8preflight/internal/model"
	"c8preflight/internal/redact"
)

// TestWriteResultJSON_Perms is the regression test asserting that the result
// file must not be world-readable. Perm bits are meaningful only on Unix; on
// Windows the create still succeeds (checked separately).
func TestWriteResultJSON_Perms(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "result.json")
	got, err := WriteResultJSON(model.Result{SchemaVersion: 1}, out, redact.Secrets{})
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if got != out {
		t.Fatalf("wrote to %q, want %q", got, out)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(out)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("result file mode = %o, want 600", fi.Mode().Perm())
		}
	}
}

// TestWriteExclusive_RefusesExisting confirms the temp-fallback writer won't
// follow/clobber a pre-planted file (the symlink/pre-creation race in finding
// #10). Cross-platform (O_EXCL works on Windows too).
func TestWriteExclusive_RefusesExisting(t *testing.T) {
	dir := t.TempDir()
	planted := filepath.Join(dir, "planted.json")
	if err := os.WriteFile(planted, []byte("attacker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeExclusive(planted, []byte("ours")); err == nil {
		t.Error("writeExclusive should refuse an already-existing path (O_EXCL)")
	}
	// A fresh path must succeed.
	fresh := filepath.Join(dir, "fresh.json")
	if err := writeExclusive(fresh, []byte("ours")); err != nil {
		t.Errorf("writeExclusive to a fresh path failed: %v", err)
	}
}
