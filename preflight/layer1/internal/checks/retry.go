package checks

import (
	"context"
	"io"
	"net/http"
	"time"
)

// backoffSchedule implements the retry policy: 3 attempts with backoff
// (~2s/4s). Index 0 is the wait before attempt 2, index 1 before attempt 3.
var backoffSchedule = []time.Duration{2 * time.Second, 4 * time.Second}

const maxAttempts = 3

// httpAttemptResult is one attempt's outcome.
type httpAttemptResult struct {
	StatusCode int
	Body       []byte
	Err        error // non-nil only for a transport-level failure (never retried)
}

// doWithRetry executes buildReq()+client.Do up to maxAttempts times, but
// ONLY retries when the caller's isRetryable callback says the HTTP status
// was an unexpected/transient one. A transport-level error (connection
// refused/timeout/DNS/TLS/407) is returned immediately on the first attempt
// and is never retried — those are real, one-shot failures.
func doWithRetry(ctx context.Context, client *http.Client, buildReq func() (*http.Request, error), isRetryable func(status int) bool) (result httpAttemptResult, attemptsUsed int, elapsedMs int64) {
	start := time.Now()

attemptLoop:
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := buildReq()
		if err != nil {
			return httpAttemptResult{Err: err}, attempt, time.Since(start).Milliseconds()
		}

		resp, err := client.Do(req)
		if err != nil {
			// Transport-level failure — never retried.
			return httpAttemptResult{Err: err}, attempt, time.Since(start).Milliseconds()
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		result = httpAttemptResult{StatusCode: resp.StatusCode, Body: body}
		attemptsUsed = attempt

		if !isRetryable(resp.StatusCode) || attempt == maxAttempts {
			break attemptLoop
		}

		select {
		case <-ctx.Done():
			break attemptLoop
		case <-time.After(backoffSchedule[attempt-1]):
		}
	}

	return result, attemptsUsed, time.Since(start).Milliseconds()
}
