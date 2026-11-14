.PHONY: deps build roothide

IH_PACKAGE_SCHEME ?= rootless
export IH_PACKAGE_SCHEME

deps:
	git submodule update --init --recursive

build:
	./scripts/build.sh

roothide:
	$(MAKE) build IH_PACKAGE_SCHEME=roothide
