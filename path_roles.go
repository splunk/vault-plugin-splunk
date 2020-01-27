package splunk

import (
	"context"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const rolesPrefix = "roles/"
const defaultUserPrefix = "vault"

func (b *backend) pathRoles() *framework.Path {
	return &framework.Path{
		Pattern: rolesPrefix + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
			"connection": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the Splunk connection this role acts on",
			},
			"default_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default TTL for role",
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Maximum time a credential is valid for",
			},
			"roles": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: "Comma-separated string or list of Splunk roles.",
			},
			"default_app": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: trimIndent(`
				User default app.  Overrides the default app inherited from the user roles.`),
			},
			"email": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "User email address.",
			},
			"tz": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "User time zone.",
			},
			"user_prefix": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Prefix for creating new users",
				Default:     defaultUserPrefix,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.rolesReadHandler,
			logical.CreateOperation: b.rolesWriteHandler,
			logical.UpdateOperation: b.rolesWriteHandler,
			logical.DeleteOperation: b.rolesDeleteHandler,
		},
		ExistenceCheck:  b.rolesExistenceCheckHandler,
		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}
}

// Returning 'true' forces an UpdateOperation, CreateOperation otherwise.
func (b *backend) rolesExistenceCheckHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)
	role, err := roleConfigLoad(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *backend) rolesReadHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	role, err := roleConfigLoad(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: role.toResponseData(),
	}
	return resp, nil
}

func (b *backend) rolesWriteHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	role, err := roleConfigLoad(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &roleConfig{}
	}

	if connRaw, ok := getValue(data, req.Operation, "connection"); ok {
		role.Connection = connRaw.(string)
	}
	if role.Connection == "" {
		return logical.ErrorResponse("empty Splunk connection name"), nil
	}
	if defaultTTLRaw, ok := getValue(data, req.Operation, "default_ttl"); ok {
		role.DefaultTTL = time.Duration(defaultTTLRaw.(int)) * time.Second
	}
	if maxTTLRaw, ok := getValue(data, req.Operation, "max_ttl"); ok {
		role.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}
	role.PasswordSpec = DefaultPasswordSpec() // XXX make configurable

	if roles, ok := getValue(data, req.Operation, "roles"); ok {
		role.Roles = roles.([]string)
	}
	if len(role.Roles) == 0 {
		return logical.ErrorResponse("roles cannot be empty"), nil
	}
	if defaultAppRaw, ok := getValue(data, req.Operation, "default_app"); ok {
		role.DefaultApp = defaultAppRaw.(string)
	}
	if emailRaw, ok := getValue(data, req.Operation, "email"); ok {
		role.Email = emailRaw.(string)
	}
	if tzRaw, ok := getValue(data, req.Operation, "tz"); ok {
		role.TZ = tzRaw.(string)
	}
	if userPrefixRaw, ok := getValue(data, req.Operation, "user_prefix"); ok {
		role.UserPrefix = userPrefixRaw.(string)
	}
	if role.UserPrefix == "" {
		return logical.ErrorResponse("user_prefix can't be set to empty string"), nil
	}

	if err := role.store(ctx, req.Storage, name); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) rolesDeleteHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if err := req.Storage.Delete(ctx, rolesPrefix+name); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathRolesList() *framework.Path {
	return &framework.Path{
		Pattern: rolesPrefix + "?$",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.rolesListHandler,
		},
		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}
}

func (b *backend) rolesListHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, rolesPrefix)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

const pathRoleHelpSyn = `
Manage the roles that can be created with this backend.
`

const pathRoleHelpDesc = `
This path lets you manage the roles that can be created with this backend.

See the documentation for roles/name for a full list of accepted
connection details.
`
