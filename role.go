package splunk

import (
	"context"
	"fmt"
	"time"

	"github.com/fatih/structs"
	"github.com/hashicorp/vault/sdk/logical"
)

type roleConfig struct {
	Connection         string        `json:"connection" structs:"connection"`
	DefaultTTL         time.Duration `json:"default_ttl" structs:"default_ttl"`
	MaxTTL             time.Duration `json:"max_ttl" structs:"max_ttl"`
	AllowedServerRoles []string      `json:"allowed_server_roles" structs:"allowed_server_roles"`
	PasswordSpec       *PasswordSpec `json:"password_spec" structs:"password_spec"`

	// Splunk user attributes
	Roles        []string `json:"roles" structs:"roles"`
	DefaultApp   string   `json:"default_app,omitempty" structs:"default_app"`
	Email        string   `json:"email,omitempty" structs:"email"`
	TZ           string   `json:"tz,omitempty" structs:"tz"`
	UserPrefix   string   `json:"user_prefix,omitempty" structs:"user_prefix"`
	UserIDScheme string   `json:"user_id_scheme,omitempty" structs:"user_id_scheme"`
}

// Role returns nil if role named `name` does not exist in `storage`, otherwise
// returns the role.  The second return value is non-nil on error.
func roleConfigLoad(ctx context.Context, s logical.Storage, name string) (*roleConfig, error) {
	if name == "" {
		return nil, fmt.Errorf("invalid role name")
	}

	entry, err := s.Get(ctx, rolesPrefix+name)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	role := roleConfig{}
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, fmt.Errorf("error decoding role: %w", err)
	}
	return &role, nil
}

func (role *roleConfig) store(ctx context.Context, s logical.Storage, name string) error {
	entry, err := logical.StorageEntryJSON(rolesPrefix+name, role)
	if err != nil {
		return err
	}
	if err := s.Put(ctx, entry); err != nil {
		return fmt.Errorf("error writing %q JSON: %w", rolesPrefix+name, err)
	}
	return nil
}

func (role *roleConfig) toResponseData() map[string]interface{} {
	data := structs.New(role).Map()
	// need to patch up TTLs because time.Duration gets garbled
	data["default_ttl"] = int64(role.DefaultTTL.Seconds())
	data["max_ttl"] = int64(role.MaxTTL.Seconds())
	return data
}
