package splunk

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// pathResetConnection configures a path to reset a plugin.
func (b *backend) pathResetConnection() *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("reset/%s", framework.GenericNameRegex("name")),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of this Splunk connection",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.connectionResetHandler,
		},

		HelpSynopsis:    pathResetConnectionHelpSyn,
		HelpDescription: pathResetConnectionHelpDesc,
	}
}

// connectionResetHandler resets a connection by clearing the existing instance
func (b *backend) connectionResetHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	config, err := connectionConfigLoad(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if err := b.clearConnection(config.ID); err != nil {
		return nil, err
	}

	return nil, nil
}

const pathResetConnectionHelpSyn = `
Resets a Splunk connection.
`

const pathResetConnectionHelpDesc = `
This path resets the Splunk connection by closing the existing
connection.  Upon further access, new connections are established.
`
