package splunk

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/dghubble/sling"
	"golang.org/x/oauth2"
)

// The Client type wraps the underlying API transport.
type Client struct {
	*sling.Sling
}

// APIParams provides the configuration for setting up a new API client with the NewClient() function.
type APIParams struct {
	BaseURL   string
	UserAgent string
	TokenTTL  time.Duration

	// pass in an actual OAuth2 client, if supported by Splunk; if nil, use Splunk's basic auth/sessionkey token flow
	AuthClient *http.Client
	oauth2.Config
}

// defaultAPIParams fills in default values for APIParams.  It is called automatically when instantiating a new Client.
func (p *APIParams) defaultAPIParams(ctx context.Context) {
	if p.BaseURL == "" {
		p.BaseURL = "https://localhost:8089"
	}
	if p.UserAgent == "" {
		p.UserAgent = "go-splunk"
	}
	if p.AuthClient == nil {
		p.AuthClient = oauth2.NewClient(ctx, p.TokenSource(ctx))
	}
	if p.TokenTTL.Nanoseconds() == 0 {
		// default for Splunk is 60 min, we keep a default 15 min buffer
		p.TokenTTL = time.Duration(45) * time.Minute
	}
}

// TokenSource returns a TokenSource using the configuration
// in params and the HTTP client from the provided context.
func (p *APIParams) TokenSource(ctx context.Context) oauth2.TokenSource {
	return oauth2.ReuseTokenSource(nil, splunkSource{ctx, p})
}

// NewClient creates a new transport for the Splunk API.
func (p *APIParams) NewClient(ctx context.Context) *Client {
	p.defaultAPIParams(ctx)

	sling := sling.New().Client(p.AuthClient).Base(p.BaseURL)
	// changing output mode requires changing response unmarshalling as well
	sling.QueryStruct(jsonOutputMode).Set("Accept", "application/json")
	sling.Set("User-Agent", p.UserAgent)

	return &Client{sling}
}

type splunkSource struct {
	ctx    context.Context
	params *APIParams
}

// Token returns a valid session token.  Cached tokens are reused until they expire, then a new token is requested.
func (ss splunkSource) Token() (*oauth2.Token, error) {
	// Obtaining a session token uses the same API conventions as the rest of the API,
	// hence we use the same API client, but without authentication (otherwise, we'd create a loop)
	p := &APIParams{
		BaseURL:   ss.params.BaseURL,
		UserAgent: ss.params.UserAgent + "/no-auth",
		// nil TokenSource => no auth
		// XXX Q: why use oauth2.NewClient in the first place?
		//     A: to get at the underlying context client
		AuthClient: oauth2.NewClient(ss.ctx, nil),
	}
	// one-time use, full API instantiation; however, the token gets cached, and this method is called infrequently
	resp, err := p.NewAPI(ss.ctx).AccessControl.Authentication.Login(ss.params.ClientID, ss.params.ClientSecret)
	if err != nil {
		return nil, err
	}

	token := &oauth2.Token{
		AccessToken: resp.SessionKey,
		TokenType:   "Splunk",
		Expiry:      time.Now().Add(ss.params.TokenTTL),
	}
	return token, nil
}

// The following functions cover the majority of modifications of the underlying transport.
// We wrap them to make their use easier.  Other modifications have to be performed directly
// on the underlying transport.

// New returns a copy of a Client for creating a new client with properties
// from a parent client.
//
// Note that query and body values are copied so if pointer values are used,
// mutating the original value will mutate the value within the child client.
func (c *Client) New() *Client {
	return &Client{c.Sling.New()}
}

// Path extends the current API client with the given path by resolving the reference to
// an absolute URL. If parsing errors occur, the client is left unmodified.
func (c *Client) Path(pathURL string) *Client {
	c.Sling.Path(pathURL)
	return c
}

// Receive kicks off an API call to the underlying transport.
// It attempts to deserialize a value into v, if there is neither a transport error nor an API error.
// Otherwise, the error is returned.
// This function also returns the full API response.
func Receive(sling *sling.Sling, v interface{}) (*Response, error) {
	apiResp := &Response{}
	apiErr := &APIError{}
	resp, err := sling.Receive(apiResp, apiErr)
	apiResp.HTTPResponse = resp
	if err != nil || !apiErr.Empty() {
		return apiResp, relevantError(err, apiErr)
	}

	if err = json.Unmarshal(apiResp.Entry, v); err != nil {
		return apiResp, relevantError(err, apiErr)
	}

	return apiResp, relevantError(nil, apiErr)
}
