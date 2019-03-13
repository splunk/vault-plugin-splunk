package splunk

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/splunk/vault-plugin-splunk/clients/splunk"
	"golang.org/x/oauth2"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func newBackend() logical.Backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config/root",
			},
		},
		Paths: []*framework.Path{
			b.pathConfigRoot(),
			b.pathConfigRotateRoot(),
			b.pathRoles(),
			b.pathListRoles(),
			b.pathCredsCreate(),
		},
		Secrets: []*framework.Secret{
			b.pathSecretCreds(),
		},
		BackendType: logical.TypeLogical,
	}
	return &b
}

type backend struct {
	*framework.Backend

	// Mutex to protect access to Splunk clients and client configs
	clientMutex sync.RWMutex
	splunkAPI   *splunk.API
}

func (b *backend) splunkClient(ctx context.Context, s logical.Storage) (*splunk.API, error) {
	b.clientMutex.RLock()
	if b.splunkAPI != nil {
		b.clientMutex.RUnlock()
		return b.splunkAPI, nil
	}

	// Upgrade the lock for writing
	b.clientMutex.RUnlock()
	b.clientMutex.Lock()
	defer b.clientMutex.Unlock()

	// check client again, in the event that a client was being created while we
	// waited for Lock()
	if b.splunkAPI != nil {
		return b.splunkAPI, nil
	}

	rawRootConfig, err := s.Get(ctx, "config/root")
	if err != nil {
		return nil, err
	}
	if rawRootConfig == nil {
		return nil, fmt.Errorf("no configuration found for config/root")
	}
	var config rootConfig
	if err := rawRootConfig.DecodeJSON(&config); err != nil {
		return nil, errwrap.Wrapf("error reading root configuration: {{err}}", err)
	}

	if config.Username == "" || config.BaseURL == "" {
		return nil, fmt.Errorf("empty username or BaseURL")
	}

	p := &splunk.APIParams{
		BaseURL: config.BaseURL,
		Config: oauth2.Config{
			ClientID:     config.Username,
			ClientSecret: config.Password,
		},
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // XXX
	}
	// client is the underlying transport for API calls, including Login (for obtaining session token)
	client := &http.Client{
		Transport: tr,
		Timeout:   1 * time.Minute,
	}
	ctx = context.WithValue(context.Background(), oauth2.HTTPClient, client)

	b.splunkAPI = p.NewAPI(ctx)
	return b.splunkAPI, nil
}

const backendHelp = `
The Splunk backend XXX.
After mounting this backend, credentials for a Splunk admin role must
be configured and roles must be written using
the "role/" endpoints before any logins can be generated.
`
