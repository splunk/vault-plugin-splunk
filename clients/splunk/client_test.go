package splunk

import (
	"testing"

	"gotest.tools/v3/assert"
)

func TestTokenSource_Token(t *testing.T) {
	ctx := TestDefaultContext()
	conn := TestGlobalSplunkClient(t)
	params := conn.Params()
	tok, err := params.TokenSource(ctx).Token()
	assert.NilError(t, err)
	assert.Assert(t, len(tok.AccessToken) > 0)
}
