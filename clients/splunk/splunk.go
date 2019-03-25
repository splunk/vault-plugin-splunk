package splunk

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

type outputMode struct {
	Mode string `url:"output_mode"`
}

var jsonOutputMode = outputMode{"json"}

// API https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTprolog
type API struct {
	params        *APIParams
	client        *Client
	Introspection *IntrospectionService
	AccessControl *AccessControlService
	// XXX ...
}

// Params returns the configuration for this API instance.
func (api *API) Params() *APIParams {
	return api.params
}

// NewAPI creates a new instance to access the API of the configured Splunk instance.
func (params *APIParams) NewAPI(ctx context.Context) *API {
	client := params.NewClient(ctx)
	paramsCopy := *params

	return &API{
		params:        &paramsCopy,
		client:        client.Path("services/"),
		Introspection: newIntrospectionService(client.New()),
		AccessControl: newAccessControlService(client.New()),
	}
}

// Response https://docs.splunk.com/Documentation/Splunk/latest/RESTUM/RESTusing#Atom_Feed_response
type Response struct {
	Title     string            `json:"title"`
	ID        string            `json:"id"`
	Updated   time.Time         `json:"updated"`
	Generator map[string]string `json:"generator"`
	Author    string            `json:"author"`
	Links     map[string]string `json:"links"` // XXX doc mismatch
	Messages  []APIErrorMessage `json:"messages"`
	Paging    Paging            `json:"paging"` // XXX doc mismatch
	Entry     json.RawMessage   `json:"entry"`

	HTTPResponse *http.Response
}

// The Paging type encapsulates paging information provided by the API.
//
// See also: https://docs.splunk.com/Documentation/Splunk/latest/RESTUM/RESTusing#Atom_Feed_response
type Paging struct {
	Offset  int `json:"offset"`
	PerPage int `json:"perPage"`
	Total   int `json:"total"`
}

// EntryMetadata https://docs.splunk.com/Documentation/Splunk/latest/RESTUM/RESTusing#Response_elements
type EntryMetadata struct {
	ACL                        // XXX doc mismatch
	Messages []APIErrorMessage `json:"messages"`
	Title    string            `json:"title"`
	ID       string            `json:"id"`
	Updated  time.Time         `json:"updated"`
	Links    map[string]string `json:"links"` // XXX doc mismatch
	Author   string            `json:"author"`
}

// ACL https://docs.splunk.com/Documentation/Splunk/7.2.4/RESTUM/RESTusing#Access_Control_List
type ACL struct {
	App            string `json:"app"`
	CanChangePerms bool   `json:"can_change_perms"`
	CanShareApp    bool   `json:"can_share_app"`
	CanShareGlobal bool   `json:"can_share_global"`
	CanShareUser   bool   `json:"can_share_user"`
	CanWrite       bool   `json:"can_write"`
	Modifiable     bool   `json:"modifiable"` // XXX doc mismatch
	Owner          string `json:"owner"`
	Perms          struct {
		Read  []string `json:"read"`
		Write []string `json:"write"`
	} `json:"perms"`
	Removable bool   `json:"removable"`
	Sharing   string `json:"sharing"`
}

// Bool is a helper routine that allocates a new bool value
// to store v and returns a pointer to it.
func Bool(v bool) *bool { return &v }

// Int is a helper routine that allocates a new int value
// to store v and returns a pointer to it.
func Int(v int) *int { return &v }

// Int64 is a helper routine that allocates a new int64 value
// to store v and returns a pointer to it.
func Int64(v int64) *int64 { return &v }

// Float64 is a helper routine that allocates a new float64 value
// to store v and returns a pointer to it.
func Float64(v float64) *float64 { return &v }

// String is a helper routine that allocates a new string value
// to store v and returns a pointer to it.
func String(v string) *string { return &v }
