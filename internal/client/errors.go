package client

import (
	"encoding/json"
	"fmt"
)

// APIError is the structured error returned for non-2xx API responses. It
// carries the request ID so a failure can be correlated with the server audit
// log without exposing response internals to every caller.
type APIError struct {
	StatusCode int    `json:"-"`
	RequestID  string `json:"-"`
	Code       string `json:"error"`
	Message    string `json:"message"`
}

// Error implements error.
func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = e.Code
	}
	if msg == "" {
		msg = "request failed"
	}
	if e.RequestID != "" {
		return fmt.Sprintf("server error (status %d, request %s): %s", e.StatusCode, e.RequestID, msg)
	}
	return fmt.Sprintf("server error (status %d): %s", e.StatusCode, msg)
}

// parseAPIError builds an APIError from a response, tolerating non-JSON bodies.
func parseAPIError(status int, requestID string, raw []byte) *APIError {
	e := &APIError{StatusCode: status, RequestID: requestID}
	if len(raw) > 0 {
		// Best-effort: many error bodies are {"error":...,"message":...}.
		_ = json.Unmarshal(raw, e)
		if e.Message == "" && e.Code == "" {
			// Fall back to the raw body, truncated to avoid noisy errors.
			body := string(raw)
			if len(body) > 256 {
				body = body[:256]
			}
			e.Message = body
		}
	}
	return e
}
