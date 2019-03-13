package splunk

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"gotest.tools/assert"
)

const (
	baseURL  = "https://localhost:18089" // XXX
	username = "admin"
	password = "GxBf3Mxsuy6(T%" // XXX
)

func testAPIParams() *APIParams {
	return &APIParams{
		BaseURL: baseURL,
		Config: oauth2.Config{
			ClientID:     username,
			ClientSecret: password,
		},
	}
}

func testContext() context.Context {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // XXX
	}
	// client is the underlying transport for API calls, including Login (for obtaining session token)
	client := &http.Client{
		Transport: tr,
		Timeout:   1 * time.Minute,
	}
	return context.WithValue(context.Background(), oauth2.HTTPClient, client)
}

func TestAuthenticationService(t *testing.T) {
	svc := testAPIParams().NewAPI(testContext()).AccessControl.Authentication
	assert.Assert(t, svc != nil)
}

func TestAuthenticationService_Login(t *testing.T) {
	svc := testAPIParams().NewAPI(testContext()).AccessControl.Authentication
	resp, err := svc.Login(username, password)
	assert.NilError(t, err)
	assert.Assert(t, len(resp.SessionKey) > 0)
	t.Logf("session key for %v: %v", username, resp.SessionKey)
}

func TestAuthenticationService_Login_Failed(t *testing.T) {
	svc := testAPIParams().NewAPI(testContext()).AccessControl.Authentication
	_, err := svc.Login("", "")
	assert.Error(t, err, "WARN splunk: Login failed")
}
