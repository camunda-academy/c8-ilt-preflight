package report

import (
	"c8preflight/internal/model"
)

// clusterProblemCodes are the remediation codes that mean "transport
// reached our cluster, but our cluster itself is the problem" — never the
// customer's network fault.
var clusterProblemCodes = map[model.ErrorClass]bool{
	model.ErrClusterUnhealthy503: true,
	model.ErrClusterEdge404:      true,
}

// networkFailCodes are real, one-shot transport failures (exit 2).
var networkFailCodes = map[model.ErrorClass]bool{
	model.ErrDNSFail:          true,
	model.ErrConnectRefused:   true,
	model.ErrConnectTimeout:   true,
	model.ErrTLSHandshakeFail: true,
	model.ErrProxyAuth407:     true,
}

// authFailCodes are full-mode-specific auth failures (exit 3).
var authFailCodes = map[model.ErrorClass]bool{
	model.ErrOAuthTokenFail:   true,
	model.ErrOAuthRateLimited: true,
	model.ErrTopologyAuthFail: true,
}

// BuildOverall computes the top-line verdict from all collected stages.
func BuildOverall(stages []model.Stage, probes []model.ProbeFragment) model.Overall {
	overall := model.Overall{Verdict: model.VerdictPass}

	for _, s := range stages {
		if clusterProblemCodes[s.RemediationCode] {
			overall.IsOurClusterProblem = true
		}
		switch s.Verdict {
		case model.VerdictFail:
			if overall.Verdict != model.VerdictFail {
				overall.Verdict = model.VerdictFail
				overall.FailingStage = s.Name
			}
		case model.VerdictWarn:
			if overall.Verdict == model.VerdictPass {
				overall.Verdict = model.VerdictWarn
			}
		}
	}

	for _, p := range probes {
		if clusterProblemCodes[p.ErrorClass] {
			overall.IsOurClusterProblem = true
		}
		switch p.Verdict {
		case model.VerdictFail, model.VerdictProbeError:
			if overall.Verdict != model.VerdictFail {
				overall.Verdict = model.VerdictFail
				if overall.FailingStage == "" {
					overall.FailingStage = "layer2:" + p.Runtime
				}
			}
		case model.VerdictWarn:
			if overall.Verdict == model.VerdictPass {
				overall.Verdict = model.VerdictWarn
			}
		}
	}

	return overall
}

// ExitCodeFor maps the result to the tool's documented exit-code table.
//
// Cluster-side codes (clusterProblemCodes) are VerdictFail today, same as
// any other blocking problem — a down shared cluster genuinely stops
// training, so severity-wise it IS a failure. But attribution is a separate
// axis: it's never the customer's fault, so it must not exit through the
// same generic-FAIL code a real customer-side problem would. The stage/probe
// fallback loops below explicitly exclude clusterProblemCodes so they fall
// through to isOurClusterProblem instead.
//
// Priority: a genuine, actionable customer-side FAIL (auth/network/config/
// probe) always wins over isOurClusterProblem. Rationale: isOurClusterProblem
// exists so a cluster-side hiccup doesn't get blamed on the customer's
// network — but if a REAL network/auth/config FAIL is present too (e.g. one
// host family genuinely blocked while, independently, the cluster is
// mid-blip on the other family), that FAIL is immediately actionable by the
// customer and must not be hidden behind "wait 5 minutes, not your fault."
// isOurClusterProblem is therefore the fallback exit code — used only when
// nothing else has genuinely failed for a reason the customer can act on.
func ExitCodeFor(result model.Result) model.ExitCode {
	for _, s := range result.Stages {
		if s.Verdict == model.VerdictFail && authFailCodes[s.RemediationCode] {
			return model.ExitFullModeAuthFail
		}
	}
	for _, s := range result.Stages {
		if s.Verdict == model.VerdictFail && networkFailCodes[s.RemediationCode] {
			return model.ExitNetworkFail
		}
	}
	for _, s := range result.Stages {
		if s.Verdict == model.VerdictFail && s.RemediationCode == model.ErrConfigError {
			return model.ExitConfigError
		}
	}
	for _, p := range result.Probes {
		if (p.Verdict == model.VerdictFail || p.Verdict == model.VerdictProbeError) && !clusterProblemCodes[p.ErrorClass] {
			return model.ExitGenericError
		}
	}
	for _, s := range result.Stages {
		if s.Verdict == model.VerdictFail && !clusterProblemCodes[s.RemediationCode] {
			return model.ExitGenericError
		}
	}

	if result.Overall.IsOurClusterProblem {
		return model.ExitOurClusterProblem
	}

	return model.ExitOK
}
