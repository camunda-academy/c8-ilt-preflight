package checks

import (
	"context"
	"net"
	"time"

	"c8preflight/internal/model"
)

// ResolveDNS performs plain hostname resolution and reports the resolved
// IPs.
func ResolveDNS(ctx context.Context, host string) model.Stage {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		return model.Stage{
			Name:            "dns",
			Host:            host,
			Verdict:         model.VerdictFail,
			RemediationCode: model.ErrDNSFail,
			Detail:          "hostname did not resolve — DNS split-horizon or no external DNS: " + err.Error(),
			ElapsedMs:       elapsed,
		}
	}

	detail := "resolved to: "
	for i, ip := range ips {
		if i > 0 {
			detail += ", "
		}
		detail += ip
	}

	return model.Stage{
		Name:            "dns",
		Host:            host,
		Verdict:         model.VerdictPass,
		RemediationCode: model.ErrOK,
		Detail:          detail,
		ElapsedMs:       elapsed,
	}
}

// ResolvedIPs is a convenience used by report building (target.resolvedIPs).
func ResolvedIPs(ctx context.Context, host string) []string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil
	}
	return ips
}
