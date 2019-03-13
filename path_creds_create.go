package splunk

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/splunk/vault-plugin-splunk/clients/splunk"
)

func (b *backend) pathCredsCreate() *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathTokenRead,
		},
	}
}

func (b *backend) pathTokenRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := b.Role(ctx, req.Storage, name)
	if err != nil {
		return nil, errwrap.Wrapf("error retrieving role: {{err}}", err)
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role %q not found", name)), nil
	}

	// Determine if we have a lease configuration
	leaseConfig, err := b.LeaseConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if leaseConfig == nil {
		leaseConfig = &configLease{}
	}

	c, err := b.splunkClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("error getting Splunk client")
	}

	// Generate credentials
	userName := fmt.Sprintf("vault-%s-%s-%d", name, req.DisplayName, time.Now().UnixNano())
	passwd, err2 := uuid.GenerateUUID()
	if err2 != nil {
		return nil, errwrap.Wrapf("error generating new password {{err}}", err2)
	}
	_, _, err3 := c.AccessControl.Authentication.Users.Create(&splunk.CreateUserOptions{
		Name:       userName,
		Password:   passwd,
		DefaultApp: role.DefaultApp,
		Email:      role.Email,
		Roles:      role.Roles,
	})
	if err3 != nil {
		return nil, err
	}

	// Use the helper to create the secret
	resp := b.Secret(secretCredsType).Response(map[string]interface{}{
		"username": userName,
		"password": passwd,
		"roles":    role.Roles,
	}, map[string]interface{}{
		"username": userName,
	})
	// XXX enforce
	resp.Secret.TTL = leaseConfig.TTL
	resp.Secret.MaxTTL = leaseConfig.MaxTTL

	return resp, nil
}
