package splunk

import (
	"testing"

	"github.com/splunk/vault-plugin-splunk/clients/splunk"
)

func TestMain(m *testing.M) {
	splunk.WithTestMainSetup(m)
}
