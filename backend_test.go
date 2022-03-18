package splunk

import (
	"context"
	"fmt"
	"testing"
	"time"

	logicaltest "github.com/hashicorp/vault/helper/testhelpers/logical"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"gotest.tools/assert"

	"github.com/splunk/vault-plugin-splunk/clients/splunk"
)

func TestBackend_basic(t *testing.T) {
	b, err := testNewSplunkBackend(t)
	if err != nil {
		t.Fatal(err)
	}

	schemes := []string{
		userIDSchemeUUID4_v0_5_0,
		userIDSchemeUUID4,
		userIDSchemeBase58_64,
		userIDSchemeBase58_128,
	}
	for _, scheme := range schemes {
		roleConfig := roleConfig{
			Connection:   "testconn",
			Roles:        []string{"admin"},
			UserPrefix:   defaultUserPrefix,
			UserIDScheme: scheme,
		}

		logicaltest.Test(t, logicaltest.TestCase{
			LogicalBackend: b,
			Steps: []logicaltest.TestStep{
				testAccStepConfig(t),
				testAccStepRole(t, "test", roleConfig),
				testAccStepCredsRead(t, "test"),
				testAccStepCredsReadMultiBadConfig(t, "test"),
			},
		})
	}
}

func TestBackend_RotateRoot(t *testing.T) {
	b, err := testNewSplunkBackend(t)
	if err != nil {
		t.Fatal(err)
	}

	logicaltest.Test(t, logicaltest.TestCase{
		LogicalBackend: b,
		Steps: []logicaltest.TestStep{
			testAccStepConfig(t),
			testAccRotateRoot(t, "testconn"),
			// and again, to check if we can still login
			testAccRotateRoot(t, "testconn"),
		},
	})
}

func TestBackend_ConnectionCRUD(t *testing.T) {
	b, err := testNewSplunkBackend(t)
	if err != nil {
		t.Fatal(err)
	}

	connConfig := splunkConfig{
		Username:       splunk.TestGlobalSplunkClient(t).Params().Config.ClientID,
		URL:            splunk.TestGlobalSplunkClient(t).Params().BaseURL,
		AllowedRoles:   []string{"*"},
		Verify:         true,
		InsecureTLS:    true,
		CAChain:        []string{},
		RootCA:         []string{},
		ConnectTimeout: time.Duration(30) * time.Second,
	}

	logicaltest.Test(t, logicaltest.TestCase{
		LogicalBackend: b,
		Steps: []logicaltest.TestStep{
			testAccStepConfig(t),
			testAccStepConnectionRead(t, "testconn", connConfig),
			testAccStepConnectionDelete(t, "testconn"),
		},
	})
}

func TestBackend_RoleCRUD(t *testing.T) {
	b, err := testNewSplunkBackend(t)
	if err != nil {
		t.Fatal(err)
	}

	testRoleConfig := roleConfig{
		Connection:         "testconn",
		Roles:              []string{"admin"},
		AllowedServerRoles: []string{"*"},
		PasswordSpec:       DefaultPasswordSpec(),
		UserPrefix:         "my-custom-prefix",
		UserIDScheme:       userIDSchemeUUID4,
	}

	logicaltest.Test(t, logicaltest.TestCase{
		LogicalBackend: b,
		Steps: []logicaltest.TestStep{
			testAccStepConfig(t),
			testAccStepRole(t, "test", testRoleConfig),
			testAccStepRoleMissingRoleName(t),
			testAccStepRoleMissingRoles(t, "MISSING"),
			testAccStepRoleRead(t, "test", testRoleConfig),
			testAccStepRoleDelete(t, "test"),
		},
	})
	emptyUserPrefixConfig := testRoleConfig
	emptyUserPrefixConfig.UserPrefix = ""
	logicaltest.Test(t, logicaltest.TestCase{
		LogicalBackend: b,
		Steps: []logicaltest.TestStep{
			testEmptyUserPrefix(t, "test", emptyUserPrefixConfig),
		},
	})

	userIDSchemeConfig := testRoleConfig
	userIDSchemeConfig.UserIDScheme = "-invalid-"
	logicaltest.Test(t, logicaltest.TestCase{
		LogicalBackend: b,
		Steps: []logicaltest.TestStep{
			testUserIDScheme(t, "test", "-invalid-", userIDSchemeConfig),
		},
	})
}

// Test steps

// Connection
func testAccStepConfig(t *testing.T) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "config/testconn",
		Data: map[string]interface{}{
			"url":           splunk.TestGlobalSplunkClient(t).Params().BaseURL,
			"username":      splunk.TestGlobalSplunkClient(t).Params().Config.ClientID,
			"password":      splunk.TestGlobalSplunkClient(t).Params().Config.ClientSecret,
			"allowed_roles": "*",
			"insecure_tls":  true,
		},
	}
}

func testAccStepConnectionRead(t *testing.T, conn string, config splunkConfig) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "config/" + conn,
		Check: func(resp *logical.Response) error {
			if resp == nil {
				return fmt.Errorf("response is nil")
			}
			expected := config.toResponseData()
			expected["id"] = resp.Data["id"].(string)
			assert.DeepEqual(t, expected, resp.Data)
			return nil
		},
	}
}

func testAccStepConnectionDelete(t *testing.T, conn string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.DeleteOperation,
		Path:      "config/" + conn,
	}
}

// Role
func testAccStepRole(t *testing.T, role string, config roleConfig) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      rolesPrefix + role,
		Data:      config.toResponseData(),
	}
}

func testAccStepRoleMissingRoles(t *testing.T, role string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      rolesPrefix + role,
		Data: map[string]interface{}{
			"connection": "testconn",
		},
		ErrorOk: true,
		Check: func(resp *logical.Response) error {
			if resp == nil {
				return fmt.Errorf("response is nil")
			}
			assert.Error(t, resp.Error(), "roles cannot be empty")
			return nil
		},
	}
}

func testAccStepRoleMissingRoleName(t *testing.T) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.CreateOperation,
		Path:      rolesPrefix,
		Data: map[string]interface{}{
			"connection": "testconn",
		},
		ErrorOk: true,
		Check: func(resp *logical.Response) error {
			if resp == nil {
				return fmt.Errorf("response is nil")
			}
			assert.Error(t, resp.Error(), "cannot write to a path ending in '/'")
			return nil
		},
	}
}

func testEmptyUserPrefix(t *testing.T, role string, config roleConfig) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.CreateOperation,
		Path:      rolesPrefix + role,
		Data:      config.toResponseData(),
		ErrorOk:   true,
		Check: func(resp *logical.Response) error {
			if resp == nil {
				return fmt.Errorf("response is nil")
			}
			assert.Error(t, resp.Error(), "user_prefix can't be set to empty string")
			return nil
		},
	}
}

func testUserIDScheme(t *testing.T, role, idScheme string, config roleConfig) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.CreateOperation,
		Path:      rolesPrefix + role,
		Data:      config.toResponseData(),
		ErrorOk:   true,
		Check: func(resp *logical.Response) error {
			if resp == nil {
				return fmt.Errorf("response is nil")
			}
			assert.Error(t, resp.Error(), fmt.Sprintf("invalid user_id_scheme: %q", idScheme))
			return nil
		},
	}
}

func testAccStepCredsRead(t *testing.T, role string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "creds/" + role,
		Check: func(resp *logical.Response) error {
			if resp == nil {
				return fmt.Errorf("response is nil")
			}
			var d struct {
				Username string `mapstructure:"username"`
				Password string `mapstructure:"password"`
				URL      string `mapstructure:"url"`
			}
			if err := mapstructure.Decode(resp.Data, &d); err != nil {
				return err
			}
			// check that generated user can login
			conn := splunk.NewTestSplunkClient(d.URL, d.Username, d.Password)
			_, _, err := conn.Introspection.ServerInfo()
			assert.NilError(t, err)

			// XXXX check that generated user is deleted if lease expires
			return nil
		},
	}
}

func testAccStepCredsReadMultiBadConfig(t *testing.T, role string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "creds/" + role + "/someNonExistentNodeID",
		ErrorOk:   true,
		Check: func(resp *logical.Response) error {
			if resp == nil {
				return fmt.Errorf("response is nil")
			}
			assert.Error(t, resp.Error(), `host "someNonExistentNodeID" not found`)
			return nil
		},
	}
}

func testAccRotateRoot(t *testing.T, conn string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "rotate-root/" + conn,
		Check: func(resp *logical.Response) error {
			if resp == nil {
				return fmt.Errorf("response is nil")
			}
			var d struct {
				Username string `mapstructure:"username"`
			}
			if err := mapstructure.Decode(resp.Data, &d); err != nil {
				return err
			}
			assert.Assert(t, d.Username != "")
			return nil
		},
	}
}

func testAccStepRoleRead(t *testing.T, role string, config roleConfig) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      rolesPrefix + role,
		Check: func(resp *logical.Response) error {
			if resp == nil {
				return fmt.Errorf("response is nil")
			}

			expected := config.toResponseData()
			assert.DeepEqual(t, expected, resp.Data)
			return nil
		},
	}
}

func testAccStepRoleDelete(t *testing.T, role string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.DeleteOperation,
		Path:      rolesPrefix + role,
	}
}

// Helpers
func testNewSplunkBackend(t *testing.T) (logical.Backend, error) {
	t.Helper()
	if splunk.TestGlobalSplunkClient(t) == nil {
		t.SkipNow()
	}
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	return Factory(context.Background(), config)
}
