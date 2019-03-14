package splunk

import (
	"context"
	"crypto/tls"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

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
	b := backend{}
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config/*",
			},
		},
		Paths: []*framework.Path{
			b.pathConfigConnection(),
			b.pathConnectionsList(),
			b.pathResetConnection(),
			b.pathRotateRoot(),
			b.pathRolesList(),
			b.pathRoles(),
			b.pathCredsCreate(),
		},
		Secrets: []*framework.Secret{
			b.pathSecretCreds(),
		},
		// Clean: XXXX
		// Invalidate: XXXX
		BackendType: logical.TypeLogical,
	}
	b.connections = make(map[string]*splunk.API)
	return &b
}

type backend struct {
	*framework.Backend
	// Mutex to protect access to Splunk clients and client configs
	sync.RWMutex
	connections map[string]*splunk.API
}

// XXXX ensureConnection
func (b *backend) GetConnection(ctx context.Context, s logical.Storage, name string) (*splunk.API, error) {
	b.RLock()
	if conn, ok := b.connections[name]; ok {
		b.RUnlock()
		return conn, nil
	}

	// Upgrade the lock for writing
	b.RUnlock()
	b.Lock()
	defer b.Unlock()

	return b.connectionUnlocked(ctx, s, name)
}

func (b *backend) connectionUnlocked(ctx context.Context, s logical.Storage, name string) (*splunk.API, error) {
	if conn, ok := b.connections[name]; ok {
		return conn, nil
	}

	// create connection
	config, err := b.connectionConfig(ctx, s, name)
	if err != nil {
		return nil, err
	}

	p := &splunk.APIParams{
		BaseURL: config.URL,
		Config: oauth2.Config{
			ClientID:     config.Username,
			ClientSecret: config.Password,
		},
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // XXXX
	}
	// client is the underlying transport for API calls, including Login (for obtaining session token)
	client := &http.Client{
		Transport: tr,
		Timeout:   1 * time.Minute,
	}
	ctx = context.WithValue(context.Background(), oauth2.HTTPClient, client)

	b.connections[name] = p.NewAPI(ctx)
	return b.connections[name], nil
}

// ClearConnection closes the connection and
// removes it from the b.connections map.
func (b *backend) ClearConnection(name string) error {
	b.Lock()
	defer b.Unlock()
	return b.clearConnectionUnlocked(name)
}

func (b *backend) clearConnectionUnlocked(name string) error {
	_, ok := b.connections[name]
	if ok {
		delete(b.connections, name)
	}
	return nil
}

func getValue(data *framework.FieldData, op logical.Operation, key string) (interface{}, bool) {
	if raw, ok := data.GetOk(key); ok {
		return raw, true
	}
	if op == logical.CreateOperation {
		return data.Get(key), true
	}
	return nil, false
}

func decodeValue(data *framework.FieldData, op logical.Operation, key string, v interface{}) error {
	raw, ok := getValue(data, op, key)
	if ok {
		rraw := reflect.ValueOf(raw)
		rv := reflect.ValueOf(v)
		rv.Elem().Set(rraw)
	}
	return nil
}

const backendHelp = `
The Splunk backend XXX.
After mounting this backend, credentials for a Splunk admin role must
be configured and roles must be written using
the "role/" endpoints before any logins can be generated.
`
