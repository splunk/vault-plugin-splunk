package splunk

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	"github.com/fatih/structs"
	"github.com/hashicorp/errwrap"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/certutil"
	"github.com/hashicorp/vault/helper/tlsutil"
	"github.com/hashicorp/vault/helper/useragent"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"golang.org/x/oauth2"

	"github.com/splunk/vault-plugin-splunk/clients/splunk"
)

const (
	respErrEmptyName = `missing or empty "name" parameter`
)

type splunkConfig struct {
	ID             string        `json:"id" structs:"id"`
	Username       string        `json:"username" structs:"username"`
	Password       string        `json:"password" structs:"password"`
	URL            string        `json:"url" structs:"url"`
	AllowedRoles   []string      `json:"allowed_roles" structs:"allowed_roles"`
	Verify         bool          `json:"verify" structs:"verify"`
	InsecureTLS    bool          `json:"insecure_tls" structs:"insecure_tls"`
	Certificate    string        `json:"certificate" structs:"certificate"`
	PrivateKey     string        `json:"private_key" structs:"private_key"`
	CAChain        []string      `json:"ca_chain" structs:"ca_chain"`
	RootCA         []string      `json:"root_ca" structs:"root_ca"`
	TLSMinVersion  string        `json:"tls_min_version" structs:"tls_min_version"`
	ConnectTimeout time.Duration `json:"connect_timeout" structs:"connect_timeout"`
}

func (config *splunkConfig) toResponseData() map[string]interface{} {
	data := structs.New(config).Map()
	data["connect_timeout"] = int64(config.ConnectTimeout.Seconds())
	data["password"] = "n/a"
	data["private_key"] = "n/a"
	return data
}

func (config *splunkConfig) toMinimalResponseData() map[string]interface{} {
	data := map[string]interface{}{
		"id":       config.ID,
		"username": config.Username,
		// "X-DEBUG-password": config.Password,
		"url": config.URL,
	}
	return data
}

func (config *splunkConfig) store(ctx context.Context, s logical.Storage, name string) (err error) {
	oldConfigID := config.ID
	if oldConfigID != "" {
		// we cannot reliably clean up the old cached connection, since some in-progress operation
		// might just call ensureConnection and reinstate it.  The window for this is the max life-time
		// of any request that was in flight during this store operation.
		//
		// Therefore, we'll have the WAL clean up after some time that's longer than the longest
		// expected response time.
		var walID string
		walID, err = framework.PutWAL(ctx, s, walTypeConn, &walConnection{oldConfigID})
		if err != nil {
			return errwrap.Wrapf("unable to create WAL for deleting cached connection: {{err}}", err)
		}

		defer func() {
			if err != nil {
				// config was not stored => cancel cleanup
				// #nosec G104
				framework.DeleteWAL(ctx, s, walID)
			}
		}()
	}

	config.ID, err = uuid.GenerateUUID()
	if err != nil {
		return errwrap.Wrapf("error generating new configuration ID: {{err}}", err)
	}

	var newEntry *logical.StorageEntry
	newEntry, err = logical.StorageEntryJSON(fmt.Sprintf("config/%s", name), config)
	if err != nil {
		return errwrap.Wrapf(fmt.Sprintf("error writing config/%s JSON: {{err}}", name), err)
	}
	if err = s.Put(ctx, newEntry); err != nil {
		return errwrap.Wrapf(fmt.Sprintf("error saving new config/%s: {{err}}", name), err)
	}

	// if config.Verify {
	// 	 config.verifyConnection(ctx, s, name)
	// }

	return err
}

func connectionConfigExists(ctx context.Context, s logical.Storage, name string) (bool, error) {
	if name == "" {
		return false, fmt.Errorf(respErrEmptyName)
	}

	entry, err := s.Get(ctx, fmt.Sprintf("config/%s", name))
	if err != nil {
		return false, errwrap.Wrapf("error reading connection configuration: {{err}}", err)
	}
	return entry != nil, nil
}

func connectionConfigLoad(ctx context.Context, s logical.Storage, name string) (*splunkConfig, error) {
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

func (config *splunkConfig) newConnection(ctx context.Context) (*splunk.API, error) {
	p := &splunk.APIParams{
		BaseURL:   config.URL,
		UserAgent: useragent.String(),
		Config: oauth2.Config{
			ClientID:     config.Username,
			ClientSecret: config.Password,
		},
	}

	tlsConfig, err := config.tlsConfig()
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	// client is the underlying transport for API calls, including Login (for obtaining session token)
	client := &http.Client{
		Transport: tr,
		Timeout:   config.ConnectTimeout,
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)

	return p.NewAPI(ctx), nil
}

func (config *splunkConfig) tlsConfig() (tlsConfig *tls.Config, err error) {
	if len(config.Certificate) > 0 || (config.CAChain != nil && len(config.CAChain) > 0) {
		if len(config.Certificate) > 0 && len(config.PrivateKey) == 0 {
			return nil, fmt.Errorf("found certificate for TLS authentication but no private key")
		}

		certBundle := &certutil.CertBundle{
			Certificate: config.Certificate,
			PrivateKey:  config.PrivateKey,
			CAChain:     config.CAChain,
		}
		parsedCertBundle, err := certBundle.ToParsedCertBundle()
		if err != nil {
			return nil, errwrap.Wrapf("failed to parse certificate bundle: {{err}}", err)
		}

		tlsConfig, err = parsedCertBundle.GetTLSConfig(certutil.TLSClient)
		if err != nil || tlsConfig == nil {
			return nil, errwrap.Wrapf(fmt.Sprintf("failed to get TLS configuration: tlsConfig: %#v; {{err}}", tlsConfig), err)
		}
	} else {
		tlsConfig = &tls.Config{}
	}

	tlsConfig.InsecureSkipVerify = config.InsecureTLS
	if config.TLSMinVersion != "" {
		var ok bool
		if tlsConfig.MinVersion, ok = tlsutil.TLSLookup[config.TLSMinVersion]; !ok {
			return nil, fmt.Errorf(`invalid "tls_min_version" in config`)
		}
	} else {
		// MinVersion was not being set earlier. Reset it to
		// zero to gracefully handle upgrades.
		tlsConfig.MinVersion = 0
	}

	if config.RootCA != nil && len(config.RootCA) > 0 {
		if tlsConfig.RootCAs == nil {
			tlsConfig.RootCAs = x509.NewCertPool()
		}
		for _, cert := range config.RootCA {
			tlsConfig.RootCAs.AppendCertsFromPEM([]byte(cert))
		}
	}

	return tlsConfig, nil
}
