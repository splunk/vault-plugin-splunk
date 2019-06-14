vault-plugin-splunk
===================

A Hashicorp Vault[1] plugin that aims to securely manage Splunk admin
accounts, including secrets rotation for compliance purposes.

[1] https://www.vaultproject.io/

## Project status

[![Build Status](https://circleci.com/gh/splunk/vault-plugin-splunk.svg?style=shield)](https://circleci.com/gh/splunk/vault-plugin-splunk)
[![GoReport](https://goreportcard.com/badge/github.com/splunk/vault-plugin-splunk)](https://goreportcard.com/report/github.com/splunk/vault-plugin-splunk)


# Building from Source

```shell
git clone git@github.com:splunk/splunk ${GOPATH}/src/github.com/splunk/vault-plugin-splunk
cd ${GOPATH}/src/github.com/splunk/vault-plugin-splunk
make
```


# Testing

## Splunk Setup

The `go test` command creates new Splunk instances for running
integration tests, which requires Docker.  Since this can be slow,
alternatively, if a `SPLUNK_ADDR` environment variable is set, this
instance will be reused.  An example for starting a new instance:

```shell
export SPLUNK_ADDR='https://localhost:8089'
export SPLUNK_PASSWORD='test1234'
docker run -d -p 8000:8000 -p 8089:8089 -e 'SPLUNK_START_ARGS=--accept-license' -e SPLUNK_PASSWORD splunk/splunk:latest
```

Integration tests can be turned off entirely by using `go test
-short`.  However, note that this disables the majority of tests,
which is not recommended.

## Vault Setup

```shell
# server
export VAULT_ADDR='http://localhost:8200'
vault server -log-level debug -dev -dev-root-token-id="root" -config=vault.hcl  # does not detach
# client use
export VAULT_ADDR='http://localhost:8200'
vault login root
```

## Rebuilding and Loading Plugin

```shell
export SPLUNK_ADDR='https://localhost:8089'
export SPLUNK_PASSWORD='test1234'
export VAULT_ADDR='http://localhost:8200'
make dev
```

## Plugin Setup

```shell
vault secrets enable -path=splunk -plugin-name=vault-plugin-splunk plugin || true
vault write splunk/config/local url="${SPLUNK_ADDR}" insecure_tls=true username=admin password="${SPLUNK_PASSWORD}" allowed_roles='*'
vault write splunk/roles/local-admin roles=admin email='test@example.com' connection=local default_ttl=30s max_ttl=5m
```

## Plugin Usage

Create temporary admin account:

    $ vault read splunk/creds/local-admin
    Key                Value
    ---                -----
    lease_id           splunk/creds/local-admin/5htFZ7QytJKbvslG5gukSPNd
    lease_duration     5m
    lease_renewable    true
    connection         local
    password           439e831b-e395-9999-2cd7-856381db3394
    roles              [admin]
    url                https://localhost:8089
    username           vault_local-admin_okta-mweber_70c6c140-238d-e12b-3289-8e38f8c4d9f5_1553712516020311000

This creates a new user account `vault_local-admin_okta-mweber_70c6...`
with a new random password.  The account was configured to have the
admin role.  It will automatically be queued for deletion by vault
after the configured lease ends, in 5 minutes.  We can use `vault
lease [renew|revoke]` to manually alter the length of the lease, up to
the configured maximum time.

Rotate the Splunk admin password:

    vault write -f splunk/rotate-root/local

NOTE: this alters the password of the configured admin account.  It
does not print out the new password.  In order not to lock yourself
out of the Splunk instance during testing, it is recommended to create
another admin account.

## Test driver

GoConvey automatically tests on saving a file:

    go get github.com/smartystreets/goconvey

Usage:

```shell
export SPLUNK_ADDR=https://localhost:8089
goconvey -excludedDirs vendor
```


# TODO

## Vault Plugin
* benchmark with thousands of simultaneous connections
* vault client cert & auto-renewal
* support "DIY" Splunk cluster without CM
* better HTTP error codes
* support for license rotation?
* add (default) secrets mount description (currently "n/a")
* DisplayName for config parameters (where is it shown?)

### Tests
* TTLs roundtrip
* externally deleted user
* externally revoked admin access
* not in allowed_roles
* updating roles, connections with partial params
* creating conns first, then roles, and vice versa

## Splunk API
* use ctx in every operation
* metrics
* error handling
* move to separate package
* generate API from OpenAPI spec
* expand doc strings
* comment strings: caps, punctuation
