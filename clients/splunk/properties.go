package splunk

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strings"
)

// PropertiesService encapsulates Splunk Properties API

type PropertiesService struct {
	client *Client
}

func newPropertiesService(client *Client) *PropertiesService {
	return &PropertiesService{
		client: client,
	}
}

type Entry struct {
	Value string
}

// stringResponseDecoder decodes http response string
// Properties API operates on particular key in the configuration file.
// CRUD for properties API returns JSON/XML encoded response for error cases and returns a string response for success
type stringResponseDecoder struct{
}

func getPropertiesUri(file string, stanza string, key string) (string) {
	return fmt.Sprintf("properties/%s/%s/%s", url.PathEscape(file), url.PathEscape(stanza), url.PathEscape(key))
}

func (d stringResponseDecoder) Decode(resp *http.Response, v interface{}) error {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if 200 <= resp.StatusCode && resp.StatusCode <= 299 {
		tempEntry := &Entry{
			Value: string(body),
		}
		vVal, tempVal := reflect.ValueOf(v), reflect.ValueOf(tempEntry)
		vVal.Elem().Set(tempVal.Elem())
		return nil
	}
	return json.Unmarshal(body, v)
}

// UpdateKey updates value for specified key from the specified stanza in the configuration file
func (p *PropertiesService) UpdateKey(file string, stanza string, key string, value string) (*string, *http.Response, error) {
	apiError := &APIError{}
	body := strings.NewReader(fmt.Sprintf("value=%s", value))
	resp, err := p.client.New().Post(
		getPropertiesUri(file, stanza, key)).Body(body).ResponseDecoder(stringResponseDecoder{}).Receive(nil, apiError)
	if err != nil || !apiError.Empty() {
		return nil, resp, relevantError(err, apiError)
	}
	return nil, resp, relevantError(err, apiError)
}

// GetKey returns value for the given key from the specified stanza in the configuration file
func (p *PropertiesService) GetKey(file string, stanza string, key string) (*string, *http.Response, error) {
	apiError := &APIError{}
	output := &Entry{}
	resp, err := p.client.New().Get(
		getPropertiesUri(file, stanza, key)).ResponseDecoder(stringResponseDecoder{}).Receive(output, apiError)
	if err != nil || !apiError.Empty() {
		return nil, resp, relevantError(err, apiError)
	}
	return &output.Value, resp, relevantError(err, apiError)
}