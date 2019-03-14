package splunk

import (
	"context"
	"fmt"
	"time"

	"github.com/fatih/structs"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const rolesPrefix = "roles/"

type roleEntry struct {
	Connection string        `json:"connection" structs:"connection"`
	DefaultTTL time.Duration `json:"default_ttl" structs:"default_ttl"`
	MaxTTL     time.Duration `json:"max_ttl" structs:"max_ttl"`

	// Splunk user attributes
	Roles      []string `json:"roles" structs:"roles"`
	DefaultApp string   `json:"default_app,omitempty" structs:"default_app"`
	Email      string   `json:"email,omitempty" structs:"email"`
	TZ         string   `json:"tz,omitempty" structs:"tz"`
}

func (role *roleEntry) toResponseData() map[string]interface{} {
	respData := structs.New(role).Map()
	// need to patch up TTLs because time.Duration gets garbled
	respData["default_ttl"] = int64(role.DefaultTTL.Seconds())
	respData["max_ttl"] = int64(role.MaxTTL.Seconds())
	return respData
}

func (b *backend) pathRolesList() *framework.Path {
	return &framework.Path{
		Pattern: rolesPrefix + "?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.rolesListHandler,
		},
	}
}

func (b *backend) rolesListHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, rolesPrefix)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

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
				Description: "Name of the connection this role acts on",
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
				Type:        framework.TypeString,
				Description: "User default app.  Overrides the default app inherited from the user roles.",
			},
			"email": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "User email address.",
			},
			"tz": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "User time zone.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.rolesReadHandler,
			logical.CreateOperation: b.rolesWriteHandler,
			logical.UpdateOperation: b.rolesWriteHandler,
			logical.DeleteOperation: b.rolesDeleteHandler,
		},

		ExistenceCheck: b.rolesExistenceCheckHandler,

		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}
}

// Role returns nil if role named `name` does not exist in `storage`, otherwise
// returns the role.  The second return value is non-nil on error.
func (b *backend) Role(ctx context.Context, storage logical.Storage, name string) (*roleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("invalid role name")
	}

	entry, err := storage.Get(ctx, rolesPrefix+name)
	if err != nil {
		return nil, errwrap.Wrapf("error retrieving role: {{err}}", err)
	}
	if entry == nil {
		return nil, nil
	}

	role := roleEntry{}
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

// Returning 'true' forces an UpdateOperation, CreateOperation otherwise.
func (b *backend) rolesExistenceCheckHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)
	role, err := b.Role(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *backend) rolesReadHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	role, err := b.Role(ctx, req.Storage, name)
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
	role, err := b.Role(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &roleEntry{}
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

	entry, err := logical.StorageEntryJSON(rolesPrefix+name, role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
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

const pathRoleHelpSyn = `
Manage the roles that can be created with this backend.
`

const pathRoleHelpDesc = `
This path lets you manage the roles that can be created with this backend.

XXX
`
