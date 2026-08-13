package checks

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"c8preflight/internal/model"
	"c8preflight/internal/redact"
)

// tokenResponse mirrors the OAuth client-credentials response shape. Fields
// are read defensively — an error body can never contain a valid
// access_token, so any non-token response is treated as a failure.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// AcquireToken performs the OAuth2 client-credentials exchange ONCE per run
// and reuses it -- the OAuth host rate-limits to roughly 1 token/sec/IP, and
// this call is on the hot path for every full-mode check.
func AcquireToken(ctx context.Context, client *http.Client, oauthURL, clientID, clientSecret, audience string) (string, model.Stage) {
	start := time.Now()
	host := hostFromURL(oauthURL)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("audience", audience)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oauthURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", model.Stage{
			Name: "oauth-token", Host: host,
			Verdict: model.VerdictFail, RemediationCode: model.ErrConfigError,
			Detail: "could not build OAuth request: " + err.Error() +
				" -- this looks like an internal problem with the tool itself, not your setup; contact the training team with this run's result file.",
		}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		code, detail := classifyDialError(err)
		return "", model.Stage{
			Name: "oauth-token", Host: host,
			Verdict: model.VerdictFail, RemediationCode: model.ErrorClass(code),
			Detail: detail, ElapsedMs: elapsed,
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode == http.StatusTooManyRequests {
		return "", model.Stage{
			Name: "oauth-token", Host: host, HTTPStatus: resp.StatusCode,
			Verdict: model.VerdictFail, RemediationCode: model.ErrOAuthRateLimited,
			Detail: "OAuth host rate-limited this request (~1 token/sec/IP shared across all clients on this network). " +
				"Stagger participant runs or rely on network mode for the bulk check.",
			ElapsedMs: elapsed,
		}
	}

	var tr tokenResponse
	if jsonErr := json.Unmarshal(body, &tr); jsonErr != nil {
		return "", model.Stage{
			Name: "oauth-token", Host: host, HTTPStatus: resp.StatusCode,
			Verdict: model.VerdictFail, RemediationCode: model.ErrOAuthTokenFail,
			Detail:    "OAuth response was not valid JSON: " + redact.Truncate(jsonErr.Error(), 200),
			ElapsedMs: elapsed,
		}
	}

	if tr.AccessToken == "" || len(tr.AccessToken) < 20 {
		reason := tr.ErrorDesc
		if reason == "" {
			reason = tr.Error
		}
		if reason == "" {
			reason = "(no error field in response)"
		}
		return "", model.Stage{
			Name: "oauth-token", Host: host, HTTPStatus: resp.StatusCode,
			Verdict: model.VerdictFail, RemediationCode: model.ErrOAuthTokenFail,
			Detail:    "OAuth returned no valid access_token. Server said: " + redact.Truncate(reason, 200),
			ElapsedMs: elapsed,
		}
	}

	return tr.AccessToken, model.Stage{
		Name: "oauth-token", Host: host, HTTPStatus: resp.StatusCode,
		Verdict: model.VerdictPass, RemediationCode: model.ErrOK,
		Detail:    "OAuth token acquired",
		ElapsedMs: elapsed,
	}
}

// CheckOAuthHostReachable performs the network-mode, credential-free OAuth
// host reachability check: a deliberately malformed/unauthenticated request
// against the token endpoint. A clean 400/401 (or any clean HTTP response)
// proves reachability — this never sends real credentials and never needs
// them.
func CheckOAuthHostReachable(ctx context.Context, client *http.Client, oauthURL string) model.Stage {
	host := hostFromURL(oauthURL)
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oauthURL, strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		return model.Stage{Name: "oauth-reachability", Host: host, Verdict: model.VerdictFail,
			RemediationCode: model.ErrConfigError, Detail: err.Error() +
				" -- this looks like an internal problem with the tool itself, not your setup; contact the training team with this run's result file."}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		code, detail := classifyDialError(err)
		return model.Stage{
			Name: "oauth-reachability", Host: host,
			Verdict: model.VerdictFail, RemediationCode: model.ErrorClass(code),
			Detail: detail, ElapsedMs: elapsed,
		}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	// Any clean HTTP response proves transport is open.
	return model.Stage{
		Name: "oauth-reachability", Host: host, HTTPStatus: resp.StatusCode,
		Verdict: model.VerdictPass, RemediationCode: model.ErrOK,
		Detail:    "OAuth host reachable (HTTP " + strconv.Itoa(resp.StatusCode) + " to an unauthenticated request proves the path is open)",
		ElapsedMs: elapsed,
	}
}

func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Hostname()
}
