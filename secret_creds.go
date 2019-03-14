package splunk

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
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
	role, err := b.Role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("error during renew: could not find role with name %q", roleName)
	}

	// Make sure we increase the VALID UNTIL endpoint for this user.
	ttl, _, err := framework.CalculateTTL(b.System(), req.Secret.Increment, role.DefaultTTL, 0, role.MaxTTL, 0, req.Secret.IssueTime)
	if err != nil {
		return nil, err
	}
	if ttl > 0 {
		expireTime := time.Now().Add(ttl)
		_ = expireTime
		// XXXX call out to Splunk if it *could* extend leases via API...
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = role.DefaultTTL
	resp.Secret.MaxTTL = role.MaxTTL
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
	c, err := b.GetConnection(ctx, req.Storage, connName)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("error getting Splunk connection")
	}

	usernameRaw, ok := req.Secret.InternalData["username"]
	if !ok {
		return nil, fmt.Errorf("username is missing on the lease")
	}
	username := usernameRaw.(string)

	// XXXX connection lock?
	_, _, err = c.AccessControl.Authentication.Users.Delete(username)
	if err != nil {
		return nil, err
	}
	return nil, nil
}
