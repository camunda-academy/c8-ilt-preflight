package checks

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"c8preflight/internal/model"
)

// WebComponentHost is one browser-facing component (name kept alongside
// host so callers get a deterministic, documented order — a Go map would
// iterate randomly and make report output vary run-to-run).
type WebComponentHost struct {
	Name string
	Host string
}

// WebComponentHosts returns the browser-facing hosts for a region, in the
// same order as NETWORK-ALLOWLIST.md's "Mandatory — Web-Component Access".
func WebComponentHosts(region string) []WebComponentHost {
	return []WebComponentHost{
		{"console", "console.cloud.camunda.io"},
		{"modeler", "modeler.cloud.camunda.io"},
		{"operate", fmt.Sprintf("%s.operate.camunda.io", region)},
		{"tasklist", fmt.Sprintf("%s.tasklist.camunda.io", region)},
		{"optimize", fmt.Sprintf("%s.optimize.camunda.io", region)},
	}
}

// CheckWebComponent is reachability-only: per NETWORK-ALLOWLIST.md, these
// hosts are browser destinations that redirect to login, so ANY clean HTTP
// response (not just 200) proves reachability — the same "clean response
// proves transport is open" principle used by the other reachability checks
// in this package.
func CheckWebComponent(ctx context.Context, client *http.Client, name, host string) model.Stage {
	start := time.Now()
	url := "https://" + host + "/"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return model.Stage{Name: "webcomponent-" + name, Host: host, Verdict: model.VerdictFail,
			RemediationCode: model.ErrConfigError, Detail: err.Error() +
				" -- this looks like an internal problem with the tool itself, not your setup; contact the training team with this run's result file."}
	}

	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		code, detail := classifyDialError(err)
		return model.Stage{
			Name: "webcomponent-" + name, Host: host,
			Verdict: model.VerdictFail, RemediationCode: model.ErrorClass(code),
			Detail: detail, ElapsedMs: elapsed,
		}
	}
	defer resp.Body.Close()

	return model.Stage{
		Name: "webcomponent-" + name, Host: host, HTTPStatus: resp.StatusCode,
		Verdict: model.VerdictPass, RemediationCode: model.ErrOK,
		Detail:    fmt.Sprintf("reachable (HTTP %d)", resp.StatusCode),
		ElapsedMs: elapsed,
	}
}
