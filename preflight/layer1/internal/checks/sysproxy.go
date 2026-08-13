package checks

// SystemProxy is what the operating system has configured as its own proxy,
// independently of the HTTP_PROXY/HTTPS_PROXY environment variables this tool
// (and Go's http.ProxyFromEnvironment) reads.
//
// The two are genuinely different sources, and on Windows they routinely
// disagree: a managed fleet configures its proxy through system settings or a
// PAC file, not through environment variables. That matters here because the
// layers don't read the same source. Layer 1 and the probes that consult the
// environment take one path, while .NET's HttpClient follows the system
// settings, so a machine can have an active proxy that Layer 1 neither uses nor
// knows about -- and reporting "no proxy detected" in that situation is a claim
// the tool cannot actually support.
//
// Detection only: this is deliberately never used to route traffic. Resolving a
// PAC file means executing its FindProxyForURL JavaScript, which the standard
// library cannot do, so any attempt to follow the system configuration
// automatically would work for simple static settings and silently mis-route
// exactly the large-enterprise setups that need it most. An operator who has
// been told a proxy exists can pass --proxy explicitly.
type SystemProxy struct {
	// Configured reports whether the OS has a proxy switched on, by either
	// mechanism below.
	Configured bool

	// Server is the static proxy setting, verbatim, when one is set. Its shape
	// is OS-defined and may name different proxies per protocol (for example
	// "http=p:80;https=q:8080") rather than being a single URL.
	Server string

	// PACURL is the auto-configuration script's location, when one is set. A PAC
	// file decides per-destination, so its presence means the effective proxy
	// cannot be known from configuration alone.
	PACURL string

	// Bypass is the list of destinations the OS is configured to reach directly.
	Bypass string

	// Supported reports whether this platform has a system proxy notion this
	// tool knows how to read; false means "not looked at", NOT "nothing set".
	Supported bool
}

// Summary renders the system proxy for humans, or "" when there's nothing to
// say. A PAC file is called out specifically: it means the answer is
// per-destination, so no single proxy address can be reported.
func (s SystemProxy) Summary() string {
	switch {
	case !s.Configured:
		return ""
	case s.PACURL != "" && s.Server != "":
		return s.Server + " (plus auto-config script " + s.PACURL + ")"
	case s.PACURL != "":
		return "auto-config script " + s.PACURL + " (the proxy it selects depends on the destination)"
	default:
		return s.Server
	}
}
