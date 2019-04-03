package splunk

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/splunk/vault-plugin-splunk/clients/splunk"
)

type backend struct {
	*framework.Backend
	conn *sync.Map
}

// Factory is the factory function to create a Splunk backend.
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
		WALRollback:       b.walRollback,
		WALRollbackMinAge: walRollbackMinAge,
		BackendType:       logical.TypeLogical,
	}
	b.conn = new(sync.Map)
	return &b
}

func (b *backend) ensureConnection(ctx context.Context, name string, config *splunkConfig) (*splunk.API, error) {
	if conn, ok := b.conn.Load(config.ID); ok {
		return conn.(*splunk.API), nil
	}

	// create and cache connection
	conn, err := config.newConnection(ctx)
	if err != nil {
		return nil, err
	}
	if conn, loaded := b.conn.LoadOrStore(config.ID, conn); loaded {
		// somebody else won the race
		return conn.(*splunk.API), nil
	}
	return conn, nil
}

// clearConnection closes the connection and removes it from the cache.
func (b *backend) clearConnection(id string) error {
	b.conn.Delete(id)
	return nil
}

const backendHelp = `
The Splunk backend rotates admin credentials and dynamically generates new
users with limited life-time.

After mounting this backend, credentials for a Splunk admin role must
be configured and connections and roles must be written using
the "config/" and "roles/" endpoints before any logins can be generated.
`
