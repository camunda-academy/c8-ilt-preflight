package checks

import (
	"runtime"
	"strings"
	"testing"
)

// TestSystemProxy_Summary pins how each configuration shape is described. The
// PAC case matters most: with an auto-config script there IS no single proxy
// address, so the summary must not imply one.
func TestSystemProxy_Summary(t *testing.T) {
	cases := []struct {
		name string
		in   SystemProxy
		want string
	}{
		{"nothing configured", SystemProxy{Supported: true}, ""},
		{
			"static server",
			SystemProxy{Supported: true, Configured: true, Server: "proxy.corp:8080"},
			"proxy.corp:8080",
		},
		{
			"pac only",
			SystemProxy{Supported: true, Configured: true, PACURL: "http://corp/proxy.pac"},
			"auto-config script http://corp/proxy.pac (the proxy it selects depends on the destination)",
		},
		{
			"both",
			SystemProxy{Supported: true, Configured: true, Server: "p:80", PACURL: "http://corp/proxy.pac"},
			"p:80 (plus auto-config script http://corp/proxy.pac)",
		},
		// Not configured wins over any leftover field values: Summary must never
		// name a proxy the machine isn't actually set up to use.
		{
			"unconfigured with stale fields",
			SystemProxy{Supported: true, Configured: false, Server: "stale:1"},
			"",
		},
	}
	for _, c := range cases {
		if got := c.in.Summary(); got != c.want {
			t.Errorf("%s: Summary() = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestDetectSystemProxy_DoesNotAffectRouting is the guarantee that keeps this
// feature honest. Detection reports what the OS has configured; it must never
// change which proxy the run actually uses, or the tool would be describing a
// path it didn't take. DetectedProxy is the routing decision and reads only the
// environment, so it has to stay indifferent to the system configuration.
func TestDetectSystemProxy_DoesNotAffectRouting(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "")

	_ = DetectSystemProxy() // whatever this machine happens to have configured

	if got := DetectedProxy("https://bru-2.api.camunda.io", ""); got != "" {
		t.Errorf("DetectedProxy = %q, want empty: routing follows the environment only, "+
			"so a system proxy must not make the tool claim it proxied this run", got)
	}
}

// TestDetectSystemProxy_PlatformSupport checks the honesty of the Supported
// flag, which exists so "looked and found nothing" is distinguishable from
// "never looked" -- reporting the latter as the former is the unsupportable
// claim this whole check was added to remove.
func TestDetectSystemProxy_PlatformSupport(t *testing.T) {
	got := DetectSystemProxy()
	wantSupported := runtime.GOOS == "windows"
	if got.Supported != wantSupported {
		t.Errorf("Supported = %v on %s, want %v", got.Supported, runtime.GOOS, wantSupported)
	}
	if !wantSupported && got.Configured {
		t.Error("an unsupported platform must never report a configured proxy")
	}
}

// TestDetectSystemProxy_NeverPanics covers the locked-down-machine case: this is
// diagnostic context, so a registry read that is denied or returns an
// unexpected type must degrade to "nothing configured" rather than take down a
// run whose actual purpose is the network checks.
func TestDetectSystemProxy_NeverPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("DetectSystemProxy panicked: %v", r)
		}
	}()
	got := DetectSystemProxy()
	// A configured proxy must always come with something to show for it,
	// otherwise the header would print an empty value after "configured:".
	if got.Configured && strings.TrimSpace(got.Summary()) == "" {
		t.Error("Configured is true but Summary() is empty")
	}
}
