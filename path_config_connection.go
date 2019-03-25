package splunk

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/helper/certutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// pathConfigConnection returns a configured framework.Path setup to
// operate on plugins.
func (b *backend) pathConfigConnection() *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("config/%s", framework.GenericNameRegex("name")),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the Splunk connection.",
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
				Description: "Splunk server URL.",
			},
			"allowed_roles": &framework.FieldSchema{
				Type: framework.TypeCommaStringSlice,
				Description: trimIndent(`
				Comma separated string or array of the role names allowed to get creds
				from this Splunk connection. If empty, no roles are allowed.  If "*", all
				roles are allowed.`),
			},
			"verify": &framework.FieldSchema{
				Type:    framework.TypeBool,
				Default: true,
				Description: trimIndent(`
				If true, the connection details are verified by actually connecting to
				Splunk.	 Default: true`),
			},
			"insecure_tls": &framework.FieldSchema{
				Type:    framework.TypeBool,
				Default: false,
				Description: trimIndent(`
				Whether to use TLS but skip verification; has no effect if a CA
				certificate is provided.  Default: false`),
			},
			"tls_min_version": &framework.FieldSchema{
				Type:    framework.TypeString,
				Default: "tls12",
				Description: trimIndent(`
				Minimum TLS version to use. Accepted values are "tls10", "tls11" or
				"tls12". Defaults to "tls12".`),
			},
			"pem_bundle": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: trimIndent(`
				PEM-format, concatenated unencrypted secret key and certificate, with
				optional CA certificate.`),
			},
			"pem_json": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: trimIndent(`
				JSON containing a PEM-format, unencrypted secret key and certificate, with
				optional CA certificate.  The JSON output of a certificate issued with the
				PKI backend can be directly passed into this parameter.  If both this and
				"pem_bundle" are specified, this will take precedence.`),
			},
			"root_ca": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `PEM-format, concatenated CA certificates.`,
			},
			"connect_timeout": &framework.FieldSchema{
				Type:        framework.TypeDurationSecond,
				Default:     "30s",
				Description: `The connection timeout to use. Default: 30s.`,
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
	return connectionConfigExists(ctx, req.Storage, name)
}

func (b *backend) connectionReadHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	config, err := connectionConfigLoad(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: config.toResponseData(),
	}
	return resp, nil
}

func (b *backend) connectionDeleteHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	config, err := connectionConfigLoad(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Delete(ctx, fmt.Sprintf("config/%s", name)); err != nil {
		return nil, errwrap.Wrapf("error reading connection configuration: {{err}}", err)
	}

	// XXXX WAL
	if err := b.clearConnection(config.ID); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) connectionWriteHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse(respErrEmptyName), nil
	}

	config := &splunkConfig{}
	if req.Operation != logical.CreateOperation {
		var err error
		config, err = connectionConfigLoad(ctx, req.Storage, name)
		if err != nil {
			return nil, errwrap.Wrapf("error reading connection configuration: {{err}}", err)
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
	// XXX go through all established leases if allowed_roles change?

	if insecureTLSRaw, ok := getValue(data, req.Operation, "insecure_tls"); ok {
		config.InsecureTLS = insecureTLSRaw.(bool)
	}

	pemBundle := data.Get("pem_bundle").(string)
	pemJSON := data.Get("pem_json").(string)
	rootCA := data.Get("root_ca").(string)

	var certBundle *certutil.CertBundle
	var parsedCertBundle *certutil.ParsedCertBundle
	var err error

	switch {
	case len(pemJSON) != 0:
		parsedCertBundle, err = certutil.ParsePKIJSON([]byte(pemJSON))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("Could not parse given JSON; it must be in the format of the output of the PKI backend certificate issuing command: %s", err)), nil
		}
		certBundle, err = parsedCertBundle.ToCertBundle()
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("Error marshaling PEM information: %s", err)), nil
		}
		config.Certificate = certBundle.Certificate
		config.PrivateKey = certBundle.PrivateKey
		config.CAChain = certBundle.CAChain

	case len(pemBundle) != 0:
		parsedCertBundle, err = certutil.ParsePEMBundle(pemBundle)
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("Error parsing the given PEM information: %s", err)), nil
		}
		certBundle, err = parsedCertBundle.ToCertBundle()
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("Error marshaling PEM information: %s", err)), nil
		}
		config.Certificate = certBundle.Certificate
		config.PrivateKey = certBundle.PrivateKey
		config.CAChain = certBundle.CAChain
	}
	if config.CAChain == nil {
		config.CAChain = []string{}
	}

	if len(rootCA) > 0 {
		config.RootCA = []string{rootCA} // XXXX parse PEM
	}
	if config.RootCA == nil {
		config.RootCA = []string{}
	}

	if connectTimeoutRaw, ok := getValue(data, req.Operation, "connect_timeout"); ok {
		config.ConnectTimeout = time.Duration(connectTimeoutRaw.(int)) * time.Second
	}

	if err := config.store(ctx, req.Storage, name); err != nil {
		return nil, errwrap.Wrapf("error writing connection configuration: {{err}}", err)
	}

	// if config.Verify {
	// 	 config.verifyConnection(ctx, req.Storage, name)
	// }

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
See the documentation for config/name for a full list of accepted
connection details.

"username", "password" and "url" are self-explanatory, although the 
given user must have admin access within Splunk.  Note that since
this backend issues username/password credentials, Splunk must be
configured to allow local users for authentication.

TLS works as follows:

* If "insecure_tls" is set to true, the connection will not perform
  verification of the server certificate

* If only "issuing_ca" is set in "pem_json", or the only certificate
  in "pem_bundle" is a CA certificate, the given CA certificate will
  be used for server certificate verification; otherwise the system CA
  certificates will be used.

* If "certificate" and "private_key" are set in "pem_bundle" or
  "pem_json", client auth will be turned on for the connection.

* If "root_ca" is set, the PEM-concatenated set of CA certificates
  will be added, and used instead of the system CA certificates.

"pem_bundle" should be a PEM-concatenated bundle of a private key +
client certificate, an issuing CA certificate, or both. "pem_json"
should contain the same information; for convenience, the JSON format
is the same as that output by the issue command from the PKI backend.

When configuring the connection information, the backend will verify
its validity.
`
