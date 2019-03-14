package splunk

import (
	"context"
	"fmt"

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
	config, err := b.connectionConfig(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	// Take out the backend lock since we are swapping out the connection
	b.Lock()
	defer b.Unlock()

	client, err := b.connectionUnlocked(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("nil Splunk client")
	}

	//  XXXX
	oldconfig := *config
	passwd, err := uuid.GenerateUUID()
	if err != nil {
		return nil, errwrap.Wrapf("error generating new password {{err}}", err)
	}
	config.Password = passwd

	opts := splunk.UpdateUserOptions{
		OldPassword: oldconfig.Password,
		Password:    config.Password,
	}
	_, _, err = client.AccessControl.Authentication.Users.Update(config.Username, &opts)
	if err != nil {
		return nil, errwrap.Wrapf("error updating password: {{err}}", err)
	}

	newEntry, err := logical.StorageEntryJSON(fmt.Sprintf("config/%s", name), config)
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("error generating new config/%s JSON: {{err}}", name), err)
	}
	if err := req.Storage.Put(ctx, newEntry); err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("error saving new config/%s: {{err}}", name), err)
	}

	b.clearConnectionUnlocked(name) // XXXX ignore errors
	// if config.Verify {
	// 	b.verifyConnection(name)
	// }

	resp := &logical.Response{
		Data: map[string]interface{}{
			"username": config.Username,
			"password": config.Password, // XXX DEBUG only, remove
		},
	}
	return resp, nil
}

const pathRotateRootHelpSyn = `
Request to rotate the Splunk credentials for a certain Splunk connection
`

const pathRotateRootHelpDesc = `
This path attempts to rotate the root credentials for the given Splunk connection.
`
