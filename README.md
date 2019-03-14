vault-plugin-splunk
-------------------

# Building from source

```shell
mkdir -p 
git clone git@github.com:splunk/splunk ${GOPATH}/src/github.com/splunk/vault-plugin-splunk
cd ${GOPATH}/src/github.com/splunk/vault-plugin-splunk
make install  # installs dep, golint etc.
make
```

# Testing


## Vault Setup

```shell
export VAULT_ADDR="https://localhost:8200"
vault server -log-level debug -dev -dev-root-token-id="root" -config=vault.hcl
vault auth root
```

## Loading Plugin

```shell
make build;
mv ~/go/bin/vault-plugin-splunk /tmp/vault-plugins/;
SHASUM=$(shasum -a 256 "/tmp/vault-plugins/vault-plugin-splunk" | cut -d " " -f1);
vault write sys/plugins/catalog/secret/vault-plugin-splunk sha_256="$SHASUM" command="vault-plugin-splunk";
curl -vk -H "X-Vault-Token: $(cat ~/.vault-token)" $VAULT_ADDR/v1/sys/plugins/reload/backend -XPUT -d '{"plugin":"vault-plugin-splunk"}'
```


# TODO
* check expiring Splunk API session tokens (renew)
* WAL?
* TLS certs, timeouts config
* comment strings: caps, punctuation
* Full name
* metrics?

* tests
** TTLs roundtrip
** externally deleted user
** externally revoked admin access
** not in allowed_roles
** updating roles, connections with partial params
** creating conns first, then roles, and vice versa
    

