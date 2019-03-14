package splunk

import (
	"context"
	"fmt"

	"github.com/fatih/structs"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	respErrEmptyName = `missing or empty "name" parameter`
)

type splunkConfig struct {
	Username     string   `json:"username" structs:"username"`
	Password     string   `json:"password" structs:"password"`
	URL          string   `json:"url" structs:"url"`
	AllowedRoles []string `json:"allowed_roles" structs:"allowed_roles"`
	Verify       bool     `json:"verify" structs:"verify"`
}

// pathConfigConnection returns a configured framework.Path setup to
// operate on plugins.
func (b *backend) pathConfigConnection() *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("config/%s", framework.GenericNameRegex("name")),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the Splunk connection",
			},
			"username": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Admin user with permission to create new accounts.",
			},
			"password": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Admin password.",
			},
			"url": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Splunk server URL",
			},
			"allowed_roles": &framework.FieldSchema{
				Type: framework.TypeCommaStringSlice,
				Description: `Comma separated string or array of the role names
				allowed to get creds from this Splunk connection. If empty no
				roles are allowed. If "*" all roles are allowed.`,
			},
			"verify": &framework.FieldSchema{
				Type:    framework.TypeBool,
				Default: true,
				Description: `If true, the connection details are verified by
				actually connecting to Splunk.  Default: true.`,
			},
		},

		ExistenceCheck: b.connectionExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.connectionWriteHandler,
			logical.UpdateOperation: b.connectionWriteHandler,
			logical.ReadOperation:   b.connectionReadHandler,
			logical.DeleteOperation: b.connectionDeleteHandler,
		},

		HelpSynopsis:    pathConfigConnectionHelpSyn,
		HelpDescription: pathConfigConnectionHelpDesc,
	}
}

func (b *backend) connectionExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	name := data.Get("name").(string)
	if name == "" {
		return false, fmt.Errorf(respErrEmptyName)
	}

	entry, err := req.Storage.Get(ctx, fmt.Sprintf("config/%s", name))
	if err != nil {
		return false, errwrap.Wrapf("error reading connection configuration: {{err}}", err)
	}
	return entry != nil, nil
}

func (b *backend) connectionConfig(ctx context.Context, s logical.Storage, name string) (*splunkConfig, error) {
	if name == "" {
		return nil, fmt.Errorf(respErrEmptyName)
	}
	entry, err := s.Get(ctx, fmt.Sprintf("config/%s", name))
	if err != nil {
		return nil, errwrap.Wrapf("error reading connection configuration: {{err}}", err)
	}
	if entry == nil {
		return nil, fmt.Errorf("connection configuration not found: %q", name)
	}

	config := splunkConfig{}
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

func (b *backend) connectionReadHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	config, err := b.connectionConfig(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	respData := structs.New(config).Map()
	respData["password"] = "n/a"
	resp := &logical.Response{
		Data: respData,
	}
	return resp, nil
}

func (b *backend) connectionDeleteHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse(respErrEmptyName), nil
	}

	err := req.Storage.Delete(ctx, fmt.Sprintf("config/%s", name))
	if err != nil {
		return nil, errwrap.Wrapf("error reading connection configuration: {{err}}", err)
	}

	if err := b.ClearConnection(name); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) connectionWriteHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	config := &splunkConfig{}
	if req.Operation != logical.CreateOperation {
		var err error
		config, err = b.connectionConfig(ctx, req.Storage, name)
		if err != nil {
			return nil, err
		}
	}

	if usernameRaw, ok := getValue(data, req.Operation, "username"); ok {
		config.Username = usernameRaw.(string)
	}
	if config.Username == "" {
		return logical.ErrorResponse("empty username"), nil
	}
	if passwordRaw, ok := getValue(data, req.Operation, "password"); ok {
		config.Password = passwordRaw.(string)
	}
	if urlRaw, ok := getValue(data, req.Operation, "url"); ok {
		config.URL = urlRaw.(string)
	}
	if config.URL == "" {
		return logical.ErrorResponse("empty URL"), nil
	}
	if verifyRaw, ok := getValue(data, req.Operation, "verify"); ok {
		config.Verify = verifyRaw.(bool)
	}
	if allowedRolesRaw, ok := getValue(data, req.Operation, "allowed_roles"); ok {
		config.AllowedRoles = allowedRolesRaw.([]string)
	}
	if len(config.AllowedRoles) == 0 {
		return logical.ErrorResponse("allowed_roles cannot be empty"), nil
	}
	// XXXX not going through all established leases if allowed_roles change

	b.Lock()
	defer b.Unlock()

	// remove old connection
	b.clearConnectionUnlocked(name)

	// store it
	entry, err := logical.StorageEntryJSON(fmt.Sprintf("config/%s", name), config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// create new connection
	if _, err := b.connectionUnlocked(ctx, req.Storage, name); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathConnectionsList() *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("config/?$"),

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.connectionListHandler,
		},

		HelpSynopsis:    pathConfigConnectionHelpSyn,
		HelpDescription: pathConfigConnectionHelpDesc,
	}
}

func (b *backend) connectionListHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "config/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

const pathConfigConnectionHelpSyn = `
Configure connection details to a Splunk instance.
`

const pathConfigConnectionHelpDesc = `
This path configures the connection details used to connect to a particular
Splunk instance.

XXXX

	* "verify" (default: true) - A boolean value denoting if the plugin should verify
	   it is able to connect to the database using the provided connection
       details.
`
