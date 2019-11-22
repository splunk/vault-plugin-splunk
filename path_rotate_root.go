package splunk

import (
	"context"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/splunk/vault-plugin-splunk/clients/splunk"
)

func (b *backend) pathRotateRoot() *framework.Path {
	return &framework.Path{
		Pattern: "rotate-root/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of this Splunk connection",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.rotateRootUpdateHandler,
		},

		HelpSynopsis:    pathRotateRootHelpSyn,
		HelpDescription: pathRotateRootHelpDesc,
	}
}

func (b *backend) rotateRootUpdateHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	oldConfig, err := connectionConfigLoad(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	conn, err := b.ensureConnection(ctx, oldConfig)
	if err != nil {
		return nil, err
	}

	config := *oldConfig
	passwd, err := uuid.GenerateUUID()
	if err != nil {
		return nil, errwrap.Wrapf("error generating new password {{err}}", err)
	}
	config.Password = passwd

	opts := splunk.UpdateUserOptions{
		OldPassword: oldConfig.Password,
		Password:    config.Password,
	}

	// XXX write WAL in case we restart between successful update and store
	if _, _, err := conn.AccessControl.Authentication.Users.Update(config.Username, &opts); err != nil {
		return nil, errwrap.Wrapf("error updating password: {{err}}", err)
	}

	if err := config.store(ctx, req.Storage, name); err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: config.toMinimalResponseData(),
	}
	return resp, nil
}

const pathRotateRootHelpSyn = `
Request to rotate the Splunk credentials for a Splunk connection.
`

const pathRotateRootHelpDesc = `
This path attempts to rotate the root credentials for the given Splunk connection.
`
