.PHONY: deps build

deps:
	git submodule update --init --recursive

build:
	./scripts/build.sh
