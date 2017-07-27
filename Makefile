PACKAGE  = stash.kopano.io/kc/konnect

# Tools

GO      = go
GOFMT   = gofmt
GLIDE   = glide
GOLINT  = golint

# Variables
PWD     := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
VERSION ?= $(shell git describe --tags --always --dirty --match=v* 2>/dev/null || \
			cat $(CURDIR)/.version 2> /dev/null || echo v0.0.0-unreleased)
GOPATH   = $(CURDIR)/.gopath
BASE     = $(GOPATH)/src/$(PACKAGE)
PKGS     = $(or $(PKG),$(shell cd $(BASE) && env GOPATH=$(GOPATH) $(GO) list ./... | grep -v "^$(PACKAGE)/vendor/"))
TESTPKGS = $(shell env GOPATH=$(GOPATH) $(GO) list -f '{{ if or .TestGoFiles .XTestGoFiles }}{{ .ImportPath }}{{ end }}' $(PKGS) 2>/dev/null)
CMDS     = $(or $(CMD),$(addprefix cmd/,$(notdir $(shell find "$(PWD)/cmd/" -type d))))
TIMEOUT  = 30

export GOPATH

# Build

.PHONY: all
all: fmt lint vendor | $(CMDS)

$(BASE): ; $(info creating local GOPATH ...)
	@mkdir -p $(dir $@)
	@ln -sf $(CURDIR) $@

.PHONY: $(CMDS)
$(CMDS): vendor | $(BASE) ; $(info building $@ ...) @
	cd $(BASE) && $(GO) build \
		-tags release \
		-ldflags '-s -w -X $(PACKAGE)/version.Version=$(VERSION) -X $(PACKAGE)/version.BuildDate=$(DATE)' \
		-o bin/$(notdir $@) $(PACKAGE)/$@

# Helpers

.PHONY: lint
lint: vendor | $(BASE) ; $(info running golint ...)	@
	@cd $(BASE) && ret=0 && for pkg in $(PKGS); do \
		test -z "$$($(GOLINT) $$pkg | tee /dev/stderr)" || ret=1 ; \
	done ; exit $$ret

.PHONY: fmt
fmt: ; $(info running gofmt ...)	@
	@ret=0 && for d in $$($(GO) list -f '{{.Dir}}' ./... | grep -v /vendor/); do \
		$(GOFMT) -l -w $$d/*.go || ret=$$? ; \
	done ; exit $$ret

# Tests

TEST_TARGETS := test-default test-short test-race test-verbose
.PHONY: $(TEST_TARGETS)
test-short:   ARGS=-short
test-race:    ARGS=-race
test-verbose: ARGS=-v
$(TEST_TARGETS): NAME=$(MAKECMDGOALS:test-%=%)
$(TEST_TARGETS): test

.PHONY: test
test: fmt lint vendor | $(BASE) ; $(info running $(NAME:%=% )tests ...)	@
	@cd $(BASE) && $(GO) test -timeout $(TIMEOUT)s $(ARGS) $(TESTPKGS)

# Glide

glide.lock: glide.yaml | $(BASE) ; $(info updating dependencies ...)
	@cd $(BASE) && $(GLIDE) update
	@touch $@

vendor: glide.lock | $(BASE) ; $(info retrieving dependencies ...)
	@cd $(BASE) && $(GLIDE) --quiet install
	@ln -nsf . vendor/src
	@touch $@

# Rest

.PHONY: clean
clean: ; $(info cleaning ...)	@
	@rm -rf $(GOPATH)
	@rm -rf bin

.PHONY: version
version:
	@echo $(VERSION)
