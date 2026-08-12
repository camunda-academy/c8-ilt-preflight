package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"c8preflight/internal/model"
	"c8preflight/internal/redact"
)

const defaultFilenamePrefix = "c8-preflight-result"

// WriteResultJSON marshals the result, runs the redaction self-check, and
// writes it to outPath if given, else the current working directory,
// falling back to the OS temp dir if that target is unwritable (locked-down
// machines often have a read-only cwd/binary dir). Returns the path actually
// written.
func WriteResultJSON(r model.Result, outPath string, secrets redact.Secrets) (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("could not marshal result: %w", err)
	}

	if reason := secrets.ScanForLeak(string(data)); reason != "" {
		return "", fmt.Errorf("REFUSING to write result: %s — this is a bug, please report it without sharing the output", reason)
	}

	// Scrub AFTER the leak scan, never before — order is load-bearing. Scrub
	// would also rewrite the hard secrets, so scrubbing first would silently
	// mask a genuine client-secret leak and rob us of the loud refuse-to-write
	// signal above (that guard exists precisely to catch our own future bugs).
	// Running it here masks the non-secret-but-still-maskable material — today
	// the client ID, which a server's error_description can reflect into a
	// Stage/Probe Detail. add() scrubs only the line it PRINTS, so without
	// this the JSON kept the raw value.
	data = []byte(secrets.Scrub(string(data)))

	path := outPath
	if path == "" {
		filename := fmt.Sprintf("%s-%s.json", defaultFilenamePrefix, time.Now().UTC().Format("20060102T150405Z"))
		cwd, err := os.Getwd()
		if err != nil {
			cwd = os.TempDir()
		}
		path = filepath.Join(cwd, filename)
	}

	// 0o600, not 0o644: the result carries the cluster's hosts/IPs and proxy
	// diagnostics, so don't make it world-readable on a shared/multi-user
	// machine.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		// Fall back to temp dir — the target (often cwd, Downloads, or
		// Program Files) may be read-only on a locked-down machine. The temp
		// dir is world-writable and the filename is predictable, so create
		// EXCLUSIVELY (O_EXCL) to avoid following/clobbering a pre-planted file
		// or symlink there.
		fallback := filepath.Join(os.TempDir(), filepath.Base(path))
		if fbErr := writeExclusive(fallback, data); fbErr != nil {
			return "", fmt.Errorf("could not write result to %q (%v) or fallback %q (%v)", path, err, fallback, fbErr)
		}
		return fallback, nil
	}

	return path, nil
}

// writeExclusive writes data to path, creating it exclusively (O_EXCL) with
// owner-only perms — so a pre-existing file or symlink at that path is a hard
// error rather than something we follow or overwrite (a temp-dir race).
func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

// WriteLogFile writes the verbose diagnostic log, applying the same
// redaction self-check — secrets must never leak into any written output,
// and the verbose log is no exception.
func WriteLogFile(path, content string, secrets redact.Secrets) error {
	if reason := secrets.ScanForLeak(content); reason != "" {
		return fmt.Errorf("REFUSING to write log file: %s", reason)
	}
	// Same scan-then-scrub ordering as WriteResultJSON — see the comment there.
	content = secrets.Scrub(content)
	// 0o600 — the verbose log is the most detailed output; least privilege.
	// NOTE: on Windows Go's file mode only drives the read-only attribute, not
	// an ACL, so "owner-only" is really "whatever the parent directory grants."
	// Acceptable here (results land in the user's own cwd/profile, which is
	// per-user by default on Windows) but do not read 0o600 as a hard
	// multi-user guarantee on that platform.
	return os.WriteFile(path, []byte(content), 0o600)
}
