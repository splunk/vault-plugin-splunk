package splunk

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

const (
	walTypeConn       = "connection"
	walRollbackMinAge = 5 * time.Minute
)

type walConnection struct {
	ID string
}

func (b *backend) walRollback(ctx context.Context, req *logical.Request, kind string, data interface{}) error {
	switch kind {
	case walTypeConn:
		return b.connectionRollback(ctx, req, data)
	default:
		return fmt.Errorf("unknown type to rollback")
	}
}

func (b *backend) connectionRollback(ctx context.Context, req *logical.Request, data interface{}) error {
	var entry walConnection
	if err := mapstructure.Decode(data, &entry); err != nil {
		return err
	}

	// remove old connection from cache
	if err := b.clearConnection(entry.ID); err != nil {
		// log and ignore errors
		b.Logger().Warn("error while clearing connection", "err", err)
	}
	return nil
}
