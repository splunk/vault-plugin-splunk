package splunk

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	rolesPrefix       = "roles/"
	defaultUserPrefix = "vault"

	userIDSchemeUUID4_v0_5_0 = ""
	userIDSchemeUUID4        = "uuid4"
	userIDSchemeBase58_64    = "base58-64"
	userIDSchemeBase58_128   = "base58-128"
)

func (b *backend) pathRoles() *framework.Path {
	return &framework.Path{
		Pattern: rolesPrefix + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
			"connection": {
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
			"roles": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Comma-separated string or list of Splunk roles.",
			},
			"allowed_server_roles": {
				Type: framework.TypeCommaStringSlice,
				Description: trimIndent(`
				Comma-separated string or array of node type (glob) patterns that are allowed
				to fetch credentials for.  If empty, no nodes are allowed.  If "*", all
				node types are allowed.`),
				Default: []string{"*"},
			},
			"default_app": {
				Type: framework.TypeString,
				Description: trimIndent(`
				User default app.  Overrides the default app inherited from the user roles.`),
			},
			"email": {
				Type:        framework.TypeString,
				Description: "User email address.",
			},
			"tz": {
				Type:        framework.TypeString,
				Description: "User time zone.",
			},
			"user_prefix": {
				Type:        framework.TypeString,
				Description: "Prefix for creating new users.",
				Default:     defaultUserPrefix,
			},
			"user_id_scheme": {
				Type: framework.TypeLowerCaseString,
				Description: fmt.Sprintf("ID generation scheme (%s, %s, %s).  Default: %s",
					userIDSchemeUUID4, userIDSchemeBase58_64, userIDSchemeBase58_128, userIDSchemeBase58_64),
				Default: userIDSchemeBase58_64,
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
	if allowedServerRoles, ok := getValue(data, req.Operation, "allowed_server_roles"); ok {
		role.AllowedServerRoles = allowedServerRoles.([]string)
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

	if userIDSchemeRaw, ok := getValue(data, req.Operation, "user_id_scheme"); ok {
		role.UserIDScheme = userIDSchemeRaw.(string)
	}
	switch role.UserIDScheme {
	case userIDSchemeUUID4_v0_5_0:
	case userIDSchemeUUID4:
	case userIDSchemeBase58_64:
	case userIDSchemeBase58_128:
	default:
		return logical.ErrorResponse("invalid user_id_scheme: %q", role.UserIDScheme), nil
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
