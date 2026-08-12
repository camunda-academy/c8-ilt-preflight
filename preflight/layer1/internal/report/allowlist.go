package report

import (
	"fmt"
	"strings"

	"c8preflight/internal/checks"
	"c8preflight/internal/hostset"
)

// AllowlistBlock renders a "send this to your network team" summary,
// generated from the resolved target rather than reading an external file
// at runtime — so the binary stays self-contained and the block is always
// accurate for the region actually being tested. See the firewall allowlist
// for the full, human-maintained reference document.
func AllowlistBlock(t hostset.Target, webComponents []checks.WebComponentHost) string {
	var b strings.Builder
	b.WriteString("\n--- Firewall allowlist (send this to your network team) ---\n")
	b.WriteString("All entries: port 443/TCP, TLS 1.2+. Outbound only, no inbound ports required.\n\n")
	fmt.Fprintf(&b, "Mandatory:\n")
	fmt.Fprintf(&b, "  %s\n", t.APIHost)
	fmt.Fprintf(&b, "  %s\n", t.ZeebeHost)
	fmt.Fprintf(&b, "  %s\n", t.OAuthHost)
	b.WriteString("\nWeb components (browser exercises):\n")
	for _, wc := range webComponents {
		fmt.Fprintf(&b, "  %s\n", wc.Host)
	}
	b.WriteString("\nAsk your training contact if you need the full reference, including gRPC and wildcard guidance.\n")
	return b.String()
}
