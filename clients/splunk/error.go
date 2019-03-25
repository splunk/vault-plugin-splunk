package splunk

import "fmt"

// The APIError type encapsulates API errors and status responses.
type APIError struct {
	Messages []APIErrorMessage `json:"messages"`
}

// The APIErrorMessage type encapsulates a single API error or status message.
type APIErrorMessage struct {
	Type string `json:"type"`
	Text string `json:"text"`
	Code string `json:"code"`
}

// Error is an implementation of the error interface
func (e APIError) Error() string {
	if len(e.Messages) > 0 {
		err := e.Messages[0] // XXX concat Messages
		s := fmt.Sprintf("%s splunk: %s", err.Type, err.Text)
		return s
	}
	return ""
}

// Empty returns true if empty. Otherwise, at least 1 error message is
// present and false is returned.
func (e APIError) Empty() bool {
	if len(e.Messages) == 0 {
		return true
	}
	return false
}

// relevantError returns any non-nil http-related error (creating the request,
// getting the response, decoding) if any. If the decoded apiError is non-zero
// the apiError is returned. Otherwise, no errors occurred, returns nil.
func relevantError(httpError error, apiError *APIError) error {
	if httpError != nil {
		return httpError
	}
	if apiError.Empty() {
		return nil
	}
	return apiError
}
