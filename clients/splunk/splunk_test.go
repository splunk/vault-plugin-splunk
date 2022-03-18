package splunk

import (
	"testing"

	"gotest.tools/v3/assert"

	"github.com/google/go-querystring/query"
)

func TestOutputMode(t *testing.T) {
	val, err := query.Values(jsonOutputMode)
	if err != nil {
		t.Error(err)
	}
	t.Log(val)
}

func TestAPIService(t *testing.T) {
	svc := TestGlobalSplunkClient(t)
	assert.Assert(t, svc != nil)
}
