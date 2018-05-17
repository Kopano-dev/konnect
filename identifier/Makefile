# Tools

YARN ?= yarn

# Variables

VERSION ?= $(shell git describe --tags --always --dirty --match=v* 2>/dev/null | sed 's/^v//' || \
			cat $(CURDIR)/../.version 2> /dev/null || echo 0.0.0-unreleased)

# Build

.PHONY: all
all: build

.yarninstall: package.json ; $(info getting depdencies with yarn ...)	@
	$(YARN) install

	@touch $@

.PHONY: build
build: .yarninstall | src ; $(info building identifier Webapp ...)	@
	@rm -rf build

	REACT_APP_KOPANO_BUILD="${VERSION}" $(YARN) run build

.PHONY: src
src:
	@$(MAKE) -C src

.PHONY: clean ; $(info cleaning identifier Webapp ...)	@
clean:
	$(YARN) cache clean
	@rm -rf build
	@rm -rf node_modules
	@rm -f .yarninstall

	@$(MAKE) -C src clean

.PHONY: version
version:
	@echo $(VERSION)
