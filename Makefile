.PHONY: deps build roothide test

IH_PACKAGE_SCHEME ?= rootless
export IH_PACKAGE_SCHEME

deps:
	git submodule update --init --recursive

build:
	./scripts/build.sh

roothide:
	$(MAKE) build IH_PACKAGE_SCHEME=roothide

test:
	@mkdir -p build/tests
	xcrun --sdk macosx clang -fobjc-arc -O2 -Wno-unused-function -Ithird_party/libroot/src -framework Foundation tests/VPNStartupTests.m -o build/tests/vpn-startup-tests
	./build/tests/vpn-startup-tests
	xcrun --sdk macosx clang -fobjc-arc -O2 -Wall -Wextra -framework Foundation tests/VPNHookDiagnosticsTests.m -o build/tests/vpn-hook-diagnostics-tests
	./build/tests/vpn-hook-diagnostics-tests
