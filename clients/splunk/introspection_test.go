package splunk

import (
	"testing"

	"gotest.tools/v3/assert"
)

func testIntrospectionService(t *testing.T) *IntrospectionService {
	return TestGlobalSplunkClient(t).Introspection
}

func TestIntrospectionService_ServerInfo(t *testing.T) {
	s := testIntrospectionService(t)

	info, resp, err := s.ServerInfo()
	assert.NilError(t, err)
	assert.Equal(t, len(info), 1)
	assert.Assert(t, info[0].ID != "")
	assert.Assert(t, len(info[0].Links) > 0)
	assert.Equal(t, resp.Paging.Offset, 0)
	_, build := resp.Generator["build"]
	assert.Assert(t, build)
	_, version := resp.Generator["version"]
	assert.Assert(t, version)

	t.Logf("%+v", info)
}
