package splunk

import (
	"testing"

	"gotest.tools/assert"
)

func testIntrospectionService() *IntrospectionService {
	return testAPIParams().NewAPI(testContext()).Introspection
}

func TestIntrospectionService_ServerInfo(t *testing.T) {
	s := testIntrospectionService()

	info, resp, err := s.ServerInfo()
	assert.NilError(t, err)
	assert.Equal(t, len(info), 1)
	assert.Assert(t, info[0].ID != "")
	assert.Assert(t, len(resp.Links) > 0)
	assert.Equal(t, resp.Paging.Offset, 0)
	_, build := resp.Generator["build"]
	assert.Assert(t, build)
	_, version := resp.Generator["version"]
	assert.Assert(t, version)

	t.Logf("%+v", info)
}
