package splunk

import (
	"context"
	"fmt"
	"strings"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/logical"
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
		return nil, fmt.Errorf("error generating new password %w", err)
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
		"url":        conn.Params().BaseURL, // new in v0.7.0
	})
	resp.Secret.TTL = role.DefaultTTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

func findNode(nodeFQDN string, hosts []splunk.ServerInfoEntry, roleConfig *roleConfig) (*splunk.ServerInfoEntry, error) {
	for _, host := range hosts {
		// check if node_fqdn is in either of HostFQDN or Host. User might not always the FQDN on the cli input
		if strings.EqualFold(host.Content.HostFQDN, nodeFQDN) || strings.EqualFold(host.Content.Host, nodeFQDN) {
			// Return host if the requested node type is allowed
			if strutil.StrListContains(roleConfig.AllowedServerRoles, "*") {
				return &host, nil
			}
			for _, role := range host.Content.Roles {
				if strutil.StrListContainsGlob(roleConfig.AllowedServerRoles, role) {
					return &host, nil
				}
			}
			return nil, fmt.Errorf("host %q does not have any of the allowed server roles: %q", nodeFQDN, roleConfig.AllowedServerRoles)
		}
	}
	return nil, fmt.Errorf("host %q not found", nodeFQDN)
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
		return nil, fmt.Errorf("unable to read searchpeers from cluster master: %w", err)
	}

	foundNode, err := findNode(nodeFQDN, nodes, role)
	if err != nil {
		return nil, err
	}
	if foundNode.Content.Host == "" {
		return nil, fmt.Errorf("host field unexpectedly empty for %q", nodeFQDN)
	}
	nodeFQDN = foundNode.Content.Host // the actual FQDN as returned by the cluster master, confusingly

	// Re-create connection for node
	conn, err = b.ensureNodeConnection(ctx, config, nodeFQDN)
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
		return nil, fmt.Errorf("error generating new password: %w", err)
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
		"url":        conn.Params().BaseURL, // new in v0.7.0
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
	switch roleConfig.UserIDScheme {
	case userIDSchemeUUID4_v0_5_0:
		fallthrough
	case userIDSchemeUUID4:
		return uuid.GenerateUUID()
	case userIDSchemeBase58_64:
		return GenerateShortUUID(8)
	case userIDSchemeBase58_128:
		return GenerateShortUUID(16)
	default:
		return "", fmt.Errorf("invalid user_id_scheme: %q", roleConfig.UserIDScheme)
	}
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
