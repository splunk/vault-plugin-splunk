VERSION         := 0.1.0
SHORT_COMMIT    := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
GO_VERSION      := $(shell go version | awk '{ print $$3}' | sed 's/^go//')

LD_FLAGS_PKG ?= main
LD_FLAGS :=
LD_FLAGS +=  -X "$(LD_FLAGS_PKG).version=$(VERSION)"
LD_FLAGS +=  -X "$(LD_FLAGS_PKG).commit=$(SHORT_COMMIT)"
LD_FLAGS +=  -X "$(LD_FLAGS_PKG).goVersion=$(GO_VERSION)"

.PHONY: all
all: get build lint test

.PHONY: get
get:
	dep ensure

.PHONY: build
build:
	go install -ldflags '$(LD_FLAGS)' ./...

.PHONY: test
test:
	go test -v ./...

.PHONY: lint
lint:
	go list ./... | grep -v vendor | xargs go vet
	go list ./... | grep -v vendor | xargs golint

.PHONY: install
install:
	go get github.com/golang/dep/cmd/dep
	go get golang.org/x/lint/golint

.PHONY: clean
clean:
	# XXX clean
	rm -rf vendor/
