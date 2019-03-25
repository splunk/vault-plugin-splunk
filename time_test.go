package splunk

import (
	"testing"
	"time"

	"github.com/fatih/structs"

	"gotest.tools/assert"
)

func TestTimeMarshalling(t *testing.T) {
	type test struct {
		TTL time.Duration `json:"ttl" structs:"ttl"`
	}

	i := 10
	s := &test{
		TTL: time.Duration(i) * time.Second,
	}
	assert.Assert(t, s.TTL.Seconds() == 10)

	m := structs.New(s).Map()

	ttl, ok := m["ttl"]
	assert.Assert(t, ok)
	assert.Assert(t, ttl.(time.Duration).Seconds() == 10)
}
