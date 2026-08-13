package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"c8preflight/internal/model"
)

type topologyResponse struct {
	Brokers []json.RawMessage `json:"brokers"`
}

// CheckTopology performs the full-mode authenticated GET /v2/topology check
// — the end-to-end confirmation that the shared credential, audience, and
// scope work.
func CheckTopology(ctx context.Context, client *http.Client, restBase, host, accessToken string) model.Stage {
	url := restBase + "/v2/topology"

	buildReq := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		return req, nil
	}
	// 401/403 are deterministic auth failures, not transient — never retry
	// those. Only unexpected 404/5xx-other get the retry treatment.
	isRetryable := func(status int) bool {
		return status != 200 && status != 401 && status != 403 && status != 503
	}

	result, attempts, elapsed := doWithRetry(ctx, client, buildReq, isRetryable)

	if result.Err != nil {
		code, detail := classifyDialError(result.Err)
		return model.Stage{
			Name: "topology", Host: host,
			Verdict: model.VerdictFail, RemediationCode: model.ErrorClass(code),
			Detail: detail, ElapsedMs: elapsed,
		}
	}

	switch result.StatusCode {
	case 200:
		var tr topologyResponse
		if err := json.Unmarshal(result.Body, &tr); err != nil || tr.Brokers == nil {
			return model.Stage{
				Name: "topology", Host: host, HTTPStatus: result.StatusCode,
				Verdict: model.VerdictFail, RemediationCode: model.ErrTopologyBadResponse,
				Detail:    "topology returned 200 but the response body did not contain a parseable 'brokers' array — unexpected API format",
				ElapsedMs: elapsed,
			}
		}
		return model.Stage{
			Name: "topology", Host: host, HTTPStatus: result.StatusCode,
			Verdict: model.VerdictPass, RemediationCode: model.ErrOK,
			Detail:    fmt.Sprintf("topology returned 200 — %d broker(s) confirmed", len(tr.Brokers)),
			ElapsedMs: elapsed,
		}
	case 401, 403:
		return model.Stage{
			Name: "topology", Host: host, HTTPStatus: result.StatusCode,
			Verdict: model.VerdictFail, RemediationCode: model.ErrTopologyAuthFail,
			Detail: fmt.Sprintf(
				"authenticated request rejected (HTTP %d) — check client id/secret are current, audience is zeebe.camunda.io, "+
					"and the client's Orchestration Cluster API scope hasn't been revoked", result.StatusCode),
			ElapsedMs: elapsed,
		}
	case 503:
		// FAIL, not WARN -- see status.go's identical reasoning: this blocks
		// training right now (severity), even though it's never the
		// customer's fault (attribution, preserved via IsOurClusterProblem).
		return model.Stage{
			Name: "topology", Host: host, HTTPStatus: result.StatusCode,
			Verdict: model.VerdictFail, RemediationCode: model.ErrClusterUnhealthy503,
			Detail:    "authenticated, but the cluster itself reports unhealthy — this is not a network or credential problem. Wait a few minutes and re-run; if it persists, contact the training team.",
			ElapsedMs: elapsed,
		}
	default:
		return model.Stage{
			Name: "topology", Host: host, HTTPStatus: result.StatusCode,
			Verdict: model.VerdictFail, RemediationCode: model.ErrClusterEdge404,
			Detail: fmt.Sprintf(
				"reached the cluster edge (HTTP %d) after %d attempt(s) but got no valid cluster route — "+
					"likely our shared cluster is paused or in a transient edge blip, not a credential or network problem. Re-run in ~5 minutes.",
				result.StatusCode, attempts),
			ElapsedMs: elapsed,
		}
	}
}
