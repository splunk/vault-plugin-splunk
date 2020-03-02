package splunk

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/errwrap"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/splunk/vault-plugin-splunk/clients/splunk"
)

func (b *backend) pathCredsCreate() *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
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

func (b *backend) pathCredsCreateMulti() *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name") + "/" + framework.GenericNameRegex("node_fqdn"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
			"node_fqdn": {
				Type:        framework.TypeString,
				Description: "FQDN for the Splunk Stack node",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.credsReadHandler,
		},

		HelpSynopsis:    pathCredsCreateHelpSyn,
		HelpDescription: pathCredsCreateHelpDesc,
	}
}

func (b *backend) credsReadHandlerStandalone(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

	conn, err := b.ensureConnection(ctx, config)
	if err != nil {
		return nil, err
	}

	// Generate credentials
	userUUID, err := generateUserID(role)
	if err != nil {
		return nil, err
	}
	userPrefix := role.UserPrefix
	if role.UserPrefix == defaultUserPrefix {
		userPrefix = fmt.Sprintf("%s_%s", role.UserPrefix, req.DisplayName)
	}
	username := fmt.Sprintf("%s_%s", userPrefix, userUUID)
	passwd, err := generateUserPassword(role)
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

func findNode(nodeFQDN string, hosts []splunk.ServerInfoEntry, roleConfig *roleConfig) (bool, error) {
	for _, host := range hosts {
		// check if node_fqdn is in either of HostFQDN or Host. User might not always the FQDN on the cli input
		if strings.EqualFold(host.Content.HostFQDN, nodeFQDN) || strings.EqualFold(host.Content.Host, nodeFQDN) {
			// Return true if the requested node type is allowed
			if strutil.StrListContains(roleConfig.AllowedServerRoles, "*") {
				return true, nil
			}
			for _, role := range host.Content.Roles {
				if strutil.StrListContainsGlob(roleConfig.AllowedServerRoles, role) {
					return true, nil
				}
			}
			return false, fmt.Errorf("host %q does not have any of the allowed server roles: %q", nodeFQDN, roleConfig.AllowedServerRoles)
		}
	}
	return false, fmt.Errorf("host %q not found", nodeFQDN)
}

func (b *backend) credsReadHandlerMulti(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	node, _ := d.GetOk("node_fqdn")
	nodeFQDN := node.(string)
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
	// Check if isStandalone is set
	if config.IsStandalone {
		return nil, fmt.Errorf("expected is_standalone to be unset for connection: %q", role.Connection)
	}

	// If role name isn't in allowed roles, send back a permission denied.
	if !strutil.StrListContains(config.AllowedRoles, "*") && !strutil.StrListContainsGlob(config.AllowedRoles, name) {
		return nil, fmt.Errorf("%q is not an allowed role for connection %q", name, role.Connection)
	}

	conn, err := b.ensureConnection(ctx, config)
	if err != nil {
		return nil, err
	}

	nodes, _, err := conn.Deployment.SearchPeers(splunk.ServerInfoEntryFilterMinimal)
	if err != nil {
		b.Logger().Error("Error while reading SearchPeers from cluster master", "err", err)
		return nil, errwrap.Wrapf("unable to read searchpeers from cluster master: {{err}}", err)
	}

	_, err = findNode(nodeFQDN, nodes, role)
	if err != nil {
		return nil, err
	}

	// Re-create connection for node
	config.URL = "https://" + nodeFQDN + ":8089"
	// XXX config.ID = ""
	conn, err = config.newConnection(ctx) // XXX cache
	if err != nil {
		return nil, err
	}
	// Generate credentials
	userUUID, err := generateUserID(role)
	if err != nil {
		return nil, err
	}
	userPrefix := role.UserPrefix
	if role.UserPrefix == defaultUserPrefix {
		userPrefix = fmt.Sprintf("%s_%s", role.UserPrefix, req.DisplayName)
	}
	username := fmt.Sprintf("%s_%s", userPrefix, userUUID)
	passwd, err := generateUserPassword(role)
	if err != nil {
		return nil, errwrap.Wrapf("error generating new password: {{err}}", err)
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
		"node_fqdn":  nodeFQDN,
	})
	resp.Secret.TTL = role.DefaultTTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

func (b *backend) credsReadHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	node_fqdn, present := d.GetOk("node_fqdn")
	// if node_fqdn is specified then the treat the request for a multi-node deployment
	if present {
		b.Logger().Debug("node_fqdn specified for role. using clustered mode for getting temporary creds", "nodeFQDN", node_fqdn.(string), "role", name)
		return b.credsReadHandlerMulti(ctx, req, d)
	}
	b.Logger().Debug("node_fqdn not specified for role. using standalone mode for getting temporary creds", "role", name)
	return b.credsReadHandlerStandalone(ctx, req, d)
}

func generateUserID(roleConfig *roleConfig) (string, error) {
	return uuid.GenerateUUID()
}

func generateUserPassword(roleConfig *roleConfig) (string, error) {
	passwd, err := GeneratePassword(roleConfig.PasswordSpec)
	if err == nil {
		return passwd, nil
	}
	// fallback
	return uuid.GenerateUUID()
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
