package splunk

import (
	"gotest.tools/assert"
	"testing"
)

func TestPropertiesService_GetKey(t *testing.T) {
	propertiesSvc := TestGlobalSplunkClient(t).Properties

	// Negative cases
	_, response, err := propertiesSvc.GetKey("foo", "bar", "key")
	assert.ErrorContains(t, err, "splunk: foo does not exist")
	assert.Equal(t, response.StatusCode, 404)
	_, response, err = propertiesSvc.GetKey("b/a/z","b-ar", "k-ey")
	assert.ErrorContains(t, err, "ERROR splunk: Directory traversal risk in /nobody/system/b/a/z at segment \"b/a/z\"")
	assert.Equal(t, response.StatusCode, 403)
	_, response, err = propertiesSvc.GetKey("foo-bar", "b/a/z", "k-ey")
	assert.ErrorContains(t, err, "splunk: foo-bar does not exist")
	assert.Equal(t, response.StatusCode, 404)
	_, response, err = propertiesSvc.UpdateKey("foo", "bar", "pass4SymmKey", "bar")
	assert.ErrorContains(t, err, "splunk: bar does not exist")
	assert.Equal(t, response.StatusCode, 404)


	_, response, _ = propertiesSvc.GetKey("server", "general", "pass4SymmKey")
	assert.Equal(t, response.StatusCode, 200)

	// Update value for pass4SymmKey and check if the new value is reflected
	_, response, _ = propertiesSvc.UpdateKey("server", "general", "pass4SymmKey", "bar")
	assert.Equal(t, response.StatusCode, 200)
	currentValue, response, _ := propertiesSvc.GetKey("server", "general", "pass4SymmKey")
	assert.Equal(t, response.StatusCode, 200)
	assert.Equal(t, *currentValue, "bar")
}
