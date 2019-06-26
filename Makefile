GOLANGCI_LINT_ARGS := --enable=gosec --enable=dupl
TESTREPORT := test-results.xml

# XXX BUG(mweber) "go env GOBIN" is empty?
GOBIN := $(shell go env GOPATH)/bin

.PHONY: all
all: build lint test

.PHONY: dep
dep: prereq
	dep ensure $(DEPFLAGS)

.PHONY: build
build: dep vault.hcl
	go install ./...

vault.hcl: vault.hcl.in
	sed -e 's;@@GOBIN@@;$(GOBIN);g' < $< > $@

.PHONY: dev
dev: build
	@test -n "$$VAULT_ADDR" || { echo 'error: environment variable VAULT_ADDR not set'; exit 1; }
	@test -f ~/.vault-token || { echo 'error: ~/.vault-token does not exist.  Use "vault auth ..." to login.'; exit 1; }
	SHASUM=$$(shasum -a 256 "$(GOBIN)/vault-plugin-splunk" | cut -d " " -f1); \
		vault write sys/plugins/catalog/secret/vault-plugin-splunk sha_256="$$SHASUM" command="vault-plugin-splunk"
	vault secrets enable -path=splunk -plugin-name=vault-plugin-splunk plugin || true
	curl -vk -H "X-Vault-Token: $$(cat ~/.vault-token)" $$VAULT_ADDR/v1/sys/plugins/reload/backend -XPUT -d '{"plugin":"vault-plugin-splunk"}'

.PHONY: test
test: build
	@test -n "$$SPLUNK_ADDR" || { echo 'warning: SPLUNK_ADDR not set, creating new Splunk instances.  This will be slow.'; }
	mkdir -p $(dir $(TESTREPORT))
	gotestsum --junitfile $(TESTREPORT) -- -cover -v ./...

.PHONY: lint
lint: dep
	golangci-lint run $(GOLANGCI_LINT_ARGS)

.PHONY: prereq
prereq:
	go get github.com/golang/dep/cmd/dep
	go get github.com/golangci/golangci-lint/cmd/golangci-lint
	go get gotest.tools/gotestsum

.PHONY: clean
clean:
	# XXX clean
	rm -rf vault.hcl $(TESTREPORT) vendor/ dist/
