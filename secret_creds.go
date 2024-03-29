package splunk

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/splunk/vault-plugin-splunk/clients/splunk"
)

const secretCredsType = "creds"

func (b *backend) pathSecretCreds() *framework.Secret {
	return &framework.Secret{
		Type:   secretCredsType,
		Fields: map[string]*framework.FieldSchema{},

		Renew:  b.secretCredsRenewHandler,
		Revoke: b.secretCredsRevokeHandler,
	}
}

func (b *backend) secretCredsRenewHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleNameRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("missing role name")
	}
	roleName := roleNameRaw.(string)
	role, err := roleConfigLoad(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("error during renew: could not find role with name %q", roleName)
	}

	nodeFQDN := ""
	nodeFQDNRaw, ok := req.Secret.InternalData["node_fqdn"]
	if ok {
		nodeFQDN = nodeFQDNRaw.(string)
	}

	// Make sure we increase the VALID UNTIL endpoint for this user.
	ttl, _, err := framework.CalculateTTL(b.System(), req.Secret.Increment, role.DefaultTTL, 0, role.MaxTTL, 0, req.Secret.IssueTime)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = role.DefaultTTL
	resp.Secret.MaxTTL = role.MaxTTL
	if ttl > 0 {
		expireTime := time.Now().Add(ttl)
		_ = expireTime
		config, err := connectionConfigLoad(ctx, req.Storage, role.Connection)
		if err != nil {
			return nil, err
		}
		conn, err := b.ensureNodeConnection(ctx, config, nodeFQDN)
		if err != nil {
			return nil, err
		}
		if conn == nil {
			return nil, fmt.Errorf("error getting Splunk connection")
		}
		if _, _, err = conn.Introspection.ServerInfo(); err != nil {
			resp.AddWarning(fmt.Sprintf("failed to renew lease: %s", err))
		}
	}
	return resp, nil
}

func (b *backend) secretCredsRevokeHandler(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	connNameRaw, ok := req.Secret.InternalData["connection"]
	if !ok {
		return nil, fmt.Errorf("no connection name was provided")
	}
	connName, ok := connNameRaw.(string)
	if !ok {
		return nil, fmt.Errorf("unable to convert connection name")
	}
	nodeFQDN := ""
	nodeFQDNRaw, ok := req.Secret.InternalData["node_fqdn"]
	if ok {
		nodeFQDN = nodeFQDNRaw.(string)
	}
	usernameRaw, ok := req.Secret.InternalData["username"]
	if !ok {
		return nil, fmt.Errorf("username is missing on the lease")
	}
	username := usernameRaw.(string)

	config, err := connectionConfigLoad(ctx, req.Storage, connName)
	if err != nil {
		return nil, err
	}
	conn, err := b.ensureNodeConnection(ctx, config, nodeFQDN)
	if err != nil {
		return nil, err
	}

	_, _, err = conn.AccessControl.Authentication.Users.Delete(username)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) ensureNodeConnection(ctx context.Context, config *splunkConfig, nodeFQDN string) (*splunk.API, error) {
	b.Logger().Debug("node connection", "nodeFQDN", nodeFQDN)
	if nodeFQDN == "" {
		return b.ensureConnection(ctx, config)
	}

	// we connect to a node, not the cluster master
	nodeConfig := *config
	nodeConfig.URL = "https://" + nodeFQDN + ":8089"
	return nodeConfig.newConnection(ctx) // XXX cache
}
