package checks

import (
	"context"
	"fmt"
	"net/http"

	"c8preflight/internal/model"
)

// CheckStatus performs the network-mode, credential-free unauthenticated
// GET /v2/status health check. 204 is the clean full PASS;
// 503 is an immediate, distinct "transport OK, cluster unhealthy" verdict
// (not retried — it's a clear, real signal, not a transient blip); any
// other unexpected status (404/5xx-other) is retried per the documented
// policy, and if still unresolved after retries is reported as
// "our cluster, not your network" rather than a customer-side FAIL.
func CheckStatus(ctx context.Context, client *http.Client, restBase, host string) model.Stage {
	url := restBase + "/v2/status"

	buildReq := func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	}
	isRetryable := func(status int) bool {
		return status != 204 && status != 503
	}

	result, attempts, elapsed := doWithRetry(ctx, client, buildReq, isRetryable)

	if result.Err != nil {
		code, detail := classifyDialError(result.Err)
		return model.Stage{
			Name: "status", Host: host,
			Verdict: model.VerdictFail, RemediationCode: model.ErrorClass(code),
			Detail: detail, ElapsedMs: elapsed,
		}
	}

	switch result.StatusCode {
	case 204:
		return model.Stage{
			Name: "status", Host: host, HTTPStatus: result.StatusCode,
			Verdict: model.VerdictPass, RemediationCode: model.ErrOK,
			Detail:    "cluster up and healthy (at least one healthy leader partition)",
			ElapsedMs: elapsed,
		}
	case 503:
		// FAIL, not WARN: the cluster genuinely can't be used for training
		// right now (severity), even though it's never the customer's fault
		// (attribution — see IsOurClusterProblem/ExitOurClusterProblem,
		// which keep that distinction correct downstream). A WARN here read
		// as "maybe still fine to proceed," which it isn't.
		return model.Stage{
			Name: "status", Host: host, HTTPStatus: result.StatusCode,
			Verdict: model.VerdictFail, RemediationCode: model.ErrClusterUnhealthy503,
			Detail:    "transport reached the cluster, but the cluster itself reports unhealthy (no healthy leader partition) — this is not a network problem. Wait a few minutes and re-run; if it persists, contact the training team.",
			ElapsedMs: elapsed,
		}
	default:
		// TLS completed and we got a clean HTTP response — this PROVES
		// transport is open, even though the status is unexpected. Never
		// report this as a customer-side network FAIL —
		// but it's still a real FAIL for THIS run (severity), just not the
		// customer's fault (attribution, via IsOurClusterProblem below).
		return model.Stage{
			Name: "status", Host: host, HTTPStatus: result.StatusCode,
			Verdict: model.VerdictFail, RemediationCode: model.ErrClusterEdge404,
			Detail: fmt.Sprintf(
				"reached the cluster edge (HTTP %d) after %d attempt(s), but got no valid cluster route — "+
					"this typically means our shared preflight cluster is paused or in a transient edge blip, "+
					"NOT a problem with your network. Re-run in ~5 minutes; if this persists, contact the training team.",
				result.StatusCode, attempts),
			ElapsedMs: elapsed,
		}
	}
}
