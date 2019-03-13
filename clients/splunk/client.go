package splunk

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/dghubble/sling"
	"golang.org/x/oauth2"
)

type Client struct {
	*sling.Sling
}

type APIParams struct {
	BaseURL   string
	UserAgent string

	// pass in an actual OAuth2 client, if supported by Splunk; if nil, use Splunk's basic auth/sessionkey token flow
	AuthClient *http.Client
	oauth2.Config
}

func (p *APIParams) DefaultAPIParams(ctx context.Context) {
	if p.BaseURL == "" {
		p.BaseURL = "https://localhost:8089"
	}
	if p.UserAgent == "" {
		p.UserAgent = "go-splunk"
	}
	if p.AuthClient == nil {
		p.AuthClient = oauth2.NewClient(ctx, p.TokenSource(ctx))
	}
}

// TokenSource returns a TokenSource using the configuration
// in params and the HTTP client from the provided context.
func (p *APIParams) TokenSource(ctx context.Context) oauth2.TokenSource {
	return oauth2.ReuseTokenSource(nil, splunkSource{ctx, p})
}

func (p *APIParams) NewClient(ctx context.Context) *Client {
	p.DefaultAPIParams(ctx)

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

func (ss splunkSource) Token() (*oauth2.Token, error) {
	// Obtaining a session token uses the same API conventions as the rest of the API,
	// hence we use the same API client, but without authentication (otherwise, we'd create a loop)
	p := &APIParams{
		BaseURL:   ss.params.BaseURL,
		UserAgent: ss.params.UserAgent + "/no-auth",
		// nil TokenSource => no auth
		// XXX Q: why use oauth2.NewClient in the first place? A: to get at the underlying context client
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
		// XXX Token Expiry? Splunk does not seem to publish TTL?
	}
	return token, nil
}

func (c *Client) New() *Client {
	return &Client{c.Sling.New()}
}

func (c *Client) Path(pathURL string) *Client {
	c.Sling.Path(pathURL)
	return c
}

func Receive(sling *sling.Sling, v interface{}) (*Response, error) {
	apiResp := &Response{}
	apiErr := &APIError{}
	resp, err := sling.Receive(apiResp, apiErr)
	apiResp.HTTPResponse = resp
	if err != nil || !apiErr.Empty() {
		return apiResp, relevantError(err, apiErr)
	}

	if err2 := json.Unmarshal(apiResp.Entry, v); err2 != nil {
		return apiResp, relevantError(err2, apiErr)
	}

	return apiResp, relevantError(nil, apiErr)
}
