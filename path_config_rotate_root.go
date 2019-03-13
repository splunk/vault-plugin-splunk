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

func (b *backend) pathConfigRotateRoot() *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate-root",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathConfigRotateRootUpdate,
		},

		HelpSynopsis:    pathConfigRotateRootHelpSyn,
		HelpDescription: pathConfigRotateRootHelpDesc,
	}
}

func (b *backend) pathConfigRotateRootUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// have to get the client config first because that takes out a read lock
	client, err := b.splunkClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("nil Splunk client")
	}

	b.clientMutex.Lock()
	defer b.clientMutex.Unlock()

	rawRootConfig, err := req.Storage.Get(ctx, "config/root")
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
		return logical.ErrorResponse("Cannot call config/rotate-root when either username or base_url is empty"), nil
	}

	//  XXX
	oldconfig := config
	passwd, err3 := uuid.GenerateUUID()
	if err3 != nil {
		return nil, errwrap.Wrapf("error generating new password {{err}}", err3)
	}
	config.Password = passwd

	_, _, err2 := client.AccessControl.Authentication.Users.Update(config.Username, &splunk.UpdateUserOptions{
		OldPassword: oldconfig.Password,
		Password:    config.Password,
	})
	if err2 != nil {
		return nil, errwrap.Wrapf("error updating password: {{err}}", err2)
	}

	newEntry, err := logical.StorageEntryJSON("config/root", config)
	if err != nil {
		return nil, errwrap.Wrapf("error generating new config/root JSON: {{err}}", err)
	}
	if err := req.Storage.Put(ctx, newEntry); err != nil {
		return nil, errwrap.Wrapf("error saving new config/root: {{err}}", err)
	}

	b.splunkAPI = nil

	return &logical.Response{
		Data: map[string]interface{}{
			"username": config.Username,
			"password": config.Password, // XXX
		},
	}, nil
}

const pathConfigRotateRootHelpSyn = `
Request to rotate the AWS credentials used by Vault
`

const pathConfigRotateRootHelpDesc = `
This path attempts to rotate the AWS credentials used by Vault for this mount.
It is only valid if Vault has been configured to use AWS IAM credentials via the
config/root endpoint.
`
