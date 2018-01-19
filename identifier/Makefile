# Tools

YARN ?= yarn

# Build

.PHONY: all
all: build

.yarninstall: package.json ; $(info getting depdencies with yarn ...)	@
	$(YARN) install

	@touch $@

.PHONY: build
build: .yarninstall | src ; $(info building identifier Webapp ...)	@
	@rm -rf build

	$(YARN) run build

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
