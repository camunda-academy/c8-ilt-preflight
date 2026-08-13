package report

import (
	"testing"

	"c8preflight/internal/model"
)

func stage(verdict model.Verdict, code model.ErrorClass) model.Stage {
	return model.Stage{Name: "test", Verdict: verdict, RemediationCode: code}
}

// Cluster-side codes are VerdictFail (not WARN) as of the severity/
// attribution split: a down shared cluster genuinely blocks training right
// now (severity), even though it's never the customer's fault (attribution,
// carried by IsOurClusterProblem/ExitOurClusterProblem below) -- status.go
// and topology.go both emit VerdictFail for these codes today.
func TestExitCodeFor_ClusterProblemAlone(t *testing.T) {
	stages := []model.Stage{stage(model.VerdictFail, model.ErrClusterUnhealthy503)}
	overall := BuildOverall(stages, nil)
	if overall.Verdict != model.VerdictFail {
		t.Fatalf("expected overall verdict FAIL (not WARN) for a cluster-side problem, got %v", overall.Verdict)
	}
	if !overall.IsOurClusterProblem {
		t.Fatal("expected IsOurClusterProblem to be true (precondition for this test)")
	}
	result := model.Result{Stages: stages, Overall: overall}
	if got := ExitCodeFor(result); got != model.ExitOurClusterProblem {
		t.Errorf("exit = %d, want %d (ExitOurClusterProblem) — a cluster-side FAIL must not fall into the generic-FAIL fallback", got, model.ExitOurClusterProblem)
	}
}

// Same scenario, but the cluster-side FAIL comes from a Layer 2 probe (e.g.
// the Java/Python/TS SDK tier's CLUSTER_UNHEALTHY_503 detection) instead of
// a Layer 1 stage -- BuildOverall must detect IsOurClusterProblem from
// probes too, not just stages, and ExitCodeFor's probe-FAIL fallback loop
// must exclude cluster-side codes the same way the stage loop does.
func TestExitCodeFor_ClusterProblemFromProbeAlone(t *testing.T) {
	probes := []model.ProbeFragment{{Runtime: "java", Verdict: model.VerdictFail, ErrorClass: model.ErrClusterUnhealthy503}}
	overall := BuildOverall(nil, probes)
	if !overall.IsOurClusterProblem {
		t.Fatal("expected IsOurClusterProblem to be detected from a probe fragment, not just stages")
	}
	result := model.Result{Probes: probes, Overall: overall}
	if got := ExitCodeFor(result); got != model.ExitOurClusterProblem {
		t.Errorf("exit = %d, want %d (ExitOurClusterProblem)", got, model.ExitOurClusterProblem)
	}
}

// A probe-error is the launcher's way of saying "this stack was only partially
// verified" — e.g. a tier that died before emitting a result, so its mandatory
// trust check never actually ran. That must escalate to an overall FAIL and a
// non-zero exit, never be reported alongside "All checks passed": a
// half-checked stack silently reading as green is the worst outcome this tool
// can produce.
func TestBuildOverall_ProbeErrorEscalatesToFail(t *testing.T) {
	probes := []model.ProbeFragment{
		{Runtime: "csharp", Target: "sdk", Verdict: model.VerdictSkip, ErrorClass: model.ErrOK},
		{Runtime: "csharp", Verdict: model.VerdictProbeError, ErrorClass: model.ErrProbeCrashed},
	}
	overall := BuildOverall([]model.Stage{stage(model.VerdictPass, model.ErrOK)}, probes)
	if overall.Verdict != model.VerdictFail {
		t.Errorf("overall verdict = %q, want FAIL — a partially-verified stack must not read as passing", overall.Verdict)
	}
	if overall.FailingStage != "layer2:csharp" {
		t.Errorf("failing stage = %q, want %q", overall.FailingStage, "layer2:csharp")
	}
	if got := ExitCodeFor(model.Result{Probes: probes, Overall: overall}); got == model.ExitOK {
		t.Error("exit code = ExitOK, want non-zero for a probe-error")
	}
}

func TestExitCodeFor_NetworkFailAlone(t *testing.T) {
	stages := []model.Stage{stage(model.VerdictFail, model.ErrConnectRefused)}
	overall := BuildOverall(stages, nil)
	result := model.Result{Stages: stages, Overall: overall}
	if got := ExitCodeFor(result); got != model.ExitNetworkFail {
		t.Errorf("exit = %d, want %d (ExitNetworkFail)", got, model.ExitNetworkFail)
	}
}

// TestExitCodeFor_NetworkFailBeatsClusterProblem is the regression test for
// the exact scenario a real test run hit: one host family genuinely blocked
// (a real, actionable customer-network FAIL) while, independently, the
// shared cluster is mid-blip on the other family (isOurClusterProblem). The
// genuine FAIL must win the exit code — a customer must never see "wait 5
// minutes, not your fault" (5) while a real, actionable block sits
// unreported in the exit code.
func TestExitCodeFor_NetworkFailBeatsClusterProblem(t *testing.T) {
	stages := []model.Stage{
		stage(model.VerdictFail, model.ErrConnectRefused), // family A: genuinely blocked
		stage(model.VerdictFail, model.ErrClusterEdge404), // family B: our cluster mid-blip (also FAIL, see severity/attribution split)
	}
	overall := BuildOverall(stages, nil)
	if !overall.IsOurClusterProblem {
		t.Fatal("expected IsOurClusterProblem to be true (precondition for this test)")
	}
	result := model.Result{Stages: stages, Overall: overall}
	if got := ExitCodeFor(result); got != model.ExitNetworkFail {
		t.Errorf("exit = %d, want %d (ExitNetworkFail) — a real FAIL must not be masked by isOurClusterProblem", got, model.ExitNetworkFail)
	}
}

func TestExitCodeFor_CleanPass(t *testing.T) {
	stages := []model.Stage{stage(model.VerdictPass, model.ErrOK)}
	overall := BuildOverall(stages, nil)
	result := model.Result{Stages: stages, Overall: overall}
	if got := ExitCodeFor(result); got != model.ExitOK {
		t.Errorf("exit = %d, want %d (ExitOK)", got, model.ExitOK)
	}
}
