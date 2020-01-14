package splunk

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/strutil"
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

		HelpSynopsis:    pathCredsCreateHelpSyn,
		HelpDescription: pathCredsCreateHelpDesc,
	}
}

func (b *backend) credsReadHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	role, err := roleConfigLoad(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role not found: %q", name)), nil
	}

	config, err := connectionConfigLoad(ctx, req.Storage, role.Connection)
	if err != nil {
		return nil, err
	}

	// If role name isn't in allowed roles, send back a permission denied.
	if !strutil.StrListContains(config.AllowedRoles, "*") && !strutil.StrListContainsGlob(config.AllowedRoles, name) {
		return nil, fmt.Errorf("%q is not an allowed role for connection %q", name, role.Connection)
	}

	conn, err := b.ensureConnection(ctx, role.Connection, config)
	if err != nil {
		return nil, err
	}

	// Generate credentials
	userUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	userPrefix := role.UserPrefix
	if role.UserPrefix == defaultUserPrefix {
		// Hash display name
		h := sha256.New()
		_, err := h.Write([]byte(req.DisplayName))
		if err != nil {
			return nil, err
		}
		bs := h.Sum(nil)
		userPrefix = fmt.Sprintf("%s_%x", role.UserPrefix, bs)
	}
	username := fmt.Sprintf("%s_%s", userPrefix, userUUID)
	passwd, err := uuid.GenerateUUID()
	if err != nil {
		return nil, errwrap.Wrapf("error generating new password {{err}}", err)
	}
	opts := splunk.CreateUserOptions{
		Name:       username,
		Password:   passwd,
		Roles:      role.Roles,
		DefaultApp: role.DefaultApp,
		Email:      role.Email,
		TZ:         role.TZ,
	}
	if _, _, err := conn.AccessControl.Authentication.Users.Create(&opts); err != nil {
		return nil, err
	}

	resp := b.Secret(secretCredsType).Response(map[string]interface{}{
		// return to user
		"username":   username,
		"password":   passwd,
		"roles":      role.Roles,
		"connection": role.Connection,
		"url":        conn.Params().BaseURL,
	}, map[string]interface{}{
		// store (with lease)
		"username":   username,
		"role":       name,
		"connection": role.Connection,
	})
	resp.Secret.TTL = role.DefaultTTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

const pathCredsCreateHelpSyn = `
Request Splunk credentials for a certain role.
`

const pathCredsCreateHelpDesc = `
This path reads Splunk credentials for a certain role. The credentials
will be generated on demand and will be automatically revoked when
their lease expires.  Leases can be extended until a configured
maximum life-time.
`
