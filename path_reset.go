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

// connectionResetHandler resets a plugin by closing the existing instance and
// creating a new one.
func (b *backend) connectionResetHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse(respErrEmptyName), nil
	}

	// delete the entry in the connections cache.
	if err := b.ClearConnection(name); err != nil {
		return nil, err
	}
	// re-create connection, we don't need the object so throw away.
	if _, err := b.GetConnection(ctx, req.Storage, name); err != nil {
		return nil, err
	}

	return nil, nil
}

const pathResetConnectionHelpSyn = `
Resets a Splunk connection.
`

const pathResetConnectionHelpDesc = `
This path resets the Splunk connection by closing the existing connection
and creating a new one.
`
