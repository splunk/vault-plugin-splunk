package splunk

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const secretCredsType = "creds"

func (b *backend) pathSecretCreds() *framework.Secret {
	return &framework.Secret{
		Type:   secretCredsType,
		Fields: map[string]*framework.FieldSchema{},

		Renew:  b.secretCredsRenew,
		Revoke: b.secretCredsRevoke,
	}
}

func (b *backend) secretCredsRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	lease, err := b.LeaseConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if lease == nil {
		lease = &configLease{}
	}
	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = lease.TTL
	resp.Secret.MaxTTL = lease.MaxTTL
	return resp, nil
}

func (b *backend) secretCredsRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	c, err := b.splunkClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("error getting Splunk client")
	}

	usernameRaw, ok := req.Secret.InternalData["username"]
	if !ok {
		return nil, fmt.Errorf("username is missing on the lease")
	}
	username, ok := usernameRaw.(string)
	if !ok {
		return nil, errors.New("unable to convert username")
	}
	_, _, err = c.AccessControl.Authentication.Users.Delete(username)
	if err != nil {
		return nil, err
	}

	return nil, nil
}
