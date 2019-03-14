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
			logical.ReadOperation: b.credsReadHandler,
		},
	}
}

func (b *backend) credsReadHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	role, err := b.Role(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role not found: %q", name)), nil
	}
	// XXXX check for allowed_roles

	c, err := b.GetConnection(ctx, req.Storage, role.Connection)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("error getting Splunk connection for role %q: %q", name, role.Connection)
	}

	// Generate credentials
	userUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	userName := fmt.Sprintf("vault_%s_%s_%s_%d", name, req.DisplayName, userUUID, time.Now().UnixNano())
	passwd, err := uuid.GenerateUUID()
	if err != nil {
		return nil, errwrap.Wrapf("error generating new password {{err}}", err)
	}
	opts := splunk.CreateUserOptions{
		Name:       userName,
		Password:   passwd,
		Roles:      role.Roles,
		DefaultApp: role.DefaultApp,
		Email:      role.Email,
		TZ:         role.TZ,
	}
	if _, _, err := c.AccessControl.Authentication.Users.Create(&opts); err != nil {
		return nil, err
	}

	resp := b.Secret(secretCredsType).Response(map[string]interface{}{
		// return to user
		"username":   userName,
		"password":   passwd,
		"roles":      role.Roles,
		"connection": role.Connection,
		"url":        c.Params().BaseURL,
	}, map[string]interface{}{
		// store (with lease)
		"username":   userName,
		"role":       name,
		"connection": role.Connection,
	})
	resp.Secret.TTL = role.DefaultTTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}
