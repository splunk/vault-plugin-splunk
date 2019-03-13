package splunk

import (
	"context"
	"errors"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func (b *backend) pathListRoles() *framework.Path {
	return &framework.Path{
		Pattern: "role/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},
	}
}

func (b *backend) pathRoles() *framework.Path {
	return &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the role",
			},

			"roles": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: "Comma-separated string or list of roles as previously created in Splunk.",
			},

			"default_app": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "User default app. Overrides the default app inherited from the user roles.",
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
			logical.ReadOperation:   b.pathRolesRead,
			logical.CreateOperation: b.pathRolesWrite,
			logical.UpdateOperation: b.pathRolesWrite,
			logical.DeleteOperation: b.pathRolesDelete,
		},

		ExistenceCheck: b.rolesExistenceCheck,

		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}
}

// Returning 'true' forces an UpdateOperation, CreateOperation otherwise.
func (b *backend) rolesExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)
	entry, err := b.Role(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *backend) Role(ctx context.Context, storage logical.Storage, name string) (*roleConfig, error) {
	if name == "" {
		return nil, errors.New("invalid role name")
	}

	entry, err := storage.Get(ctx, "role/"+name)
	if err != nil {
		return nil, errwrap.Wrapf("error retrieving role: {{err}}", err)
	}
	if entry == nil {
		return nil, nil
	}

	var result roleConfig
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := b.Role(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	// Generate the response
	resp := &logical.Response{
		Data: map[string]interface{}{
			"roles":       role.Roles,
			"email":       role.Email,
			"default_app": role.DefaultApp,
			"tz":          role.TZ,
		},
	}
	return resp, nil
}

func (b *backend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := b.Role(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = new(roleConfig)
	}

	roles, ok := d.GetOk("roles")
	if ok {
		role.Roles = roles.([]string)
	}
	if len(role.Roles) == 0 {
		return logical.ErrorResponse("roles cannot be empty"), nil
	}
	role.DefaultApp = d.Get("default_app").(string)
	role.Email = d.Get("email").(string)
	role.TZ = d.Get("tz").(string)

	entry, err := logical.StorageEntryJSON("role/"+name, role)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if err := req.Storage.Delete(ctx, "role/"+name); err != nil {
		return nil, err
	}
	return nil, nil
}

type roleConfig struct {
	Roles      []string `json:"roles"`
	DefaultApp string   `json:"defaultApp"`
	Email      string   `json:"email"`
	TZ         string   `json:"tz"`
}

const pathRoleHelpSyn = `
Manage the roles that can be created with this backend.
`

const pathRoleHelpDesc = `
This path lets you manage the roles that can be created with this backend.

XXX
`
