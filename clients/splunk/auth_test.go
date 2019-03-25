package splunk

import (
	"testing"

	"gotest.tools/assert"
)

func TestAuthenticationService(t *testing.T) {
	svc := TestGlobalSplunkClient(t).AccessControl.Authentication
	assert.Assert(t, svc != nil)
}

func TestAuthenticationService_Login(t *testing.T) {
	svc := TestGlobalSplunkClient(t).AccessControl.Authentication
	username := testGlobalSplunkConn.Params().ClientID
	password := testGlobalSplunkConn.Params().ClientSecret
	resp, err := svc.Login(username, password)
	assert.NilError(t, err)
	assert.Assert(t, len(resp.SessionKey) > 0)
	t.Logf("session key for %q: %v", username, resp.SessionKey)
}

func TestAuthenticationService_Login_Failed(t *testing.T) {
	svc := TestGlobalSplunkClient(t).AccessControl.Authentication
	_, err := svc.Login("", "")
	assert.Error(t, err, "WARN splunk: Login failed")
}
