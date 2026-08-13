//go:build !windows

package checks

// DetectSystemProxy reports "not supported" everywhere except Windows.
//
// macOS and Linux are left out on purpose rather than for lack of an API. The
// gap this closes is specific to Windows: there, the environment variables this
// tool reads and the system settings .NET follows are separate sources that
// routinely disagree, so "no proxy detected" can be wrong. On macOS and Linux
// the toolchains involved in a training setup read the same HTTP_PROXY/
// HTTPS_PROXY variables Layer 1 already reports, so there is no second source
// to reconcile and claiming one would only add noise.
//
// Supported stays false so callers can tell "looked and found nothing" apart
// from "never looked" -- reporting the latter as the former would be the same
// kind of unsupportable claim this whole check exists to remove.
func DetectSystemProxy() SystemProxy {
	return SystemProxy{Supported: false}
}
