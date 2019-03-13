package splunk

import (
	"testing"

	"gotest.tools/assert"
)

func TestTokenSource_Token(t *testing.T) {
	ctx := testContext()
	params := testAPIParams()
	params.DefaultAPIParams(ctx)
	tok, err := params.TokenSource(ctx).Token()
	assert.NilError(t, err)
	assert.Assert(t, len(tok.AccessToken) > 0)
}
