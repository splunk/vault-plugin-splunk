package splunk

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func (b *backend) pathConfigRoot() *framework.Path {
	return &framework.Path{
		Pattern: "config/root",
		Fields: map[string]*framework.FieldSchema{
			"username": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Admin user with permission to create new keys.",
			},

			"password": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "admin password.",
			},

			"base_url": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Splunk server URL",
			},
			"max_retries": &framework.FieldSchema{
				Type:        framework.TypeInt,
				Default:     5, // XXX
				Description: "Maximum number of retries for recoverable exceptions of Splunk APIs",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathConfigRootWrite,
		},

		HelpSynopsis:    pathConfigRootHelpSyn,
		HelpDescription: pathConfigRootHelpDesc,
	}
}

func (b *backend) pathConfigRootWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	maxretries := data.Get("max_retries").(int)

	b.clientMutex.Lock()
	defer b.clientMutex.Unlock()

	entry, err := logical.StorageEntryJSON("config/root", rootConfig{
		Username:   data.Get("username").(string),
		Password:   data.Get("password").(string),
		BaseURL:    data.Get("base_url").(string),
		MaxRetries: maxretries,
	})
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.splunkAPI = nil

	return nil, nil
}

type rootConfig struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	BaseURL    string `json:"base_url"`
	MaxRetries int    `json:"max_retries"`
}

const pathConfigRootHelpSyn = `
Configure the root credentials that are used to manage Splunk.
`

const pathConfigRootHelpDesc = `
Before doing anything, the Splunk backend needs credentials that are able
to manage roles, users, access keys, etc. This endpoint is used
to configure those credentials. They don't necessarily need to be admin
credentials as long as they have permission to manage users.
`
