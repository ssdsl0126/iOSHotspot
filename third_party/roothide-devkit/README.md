# RootHide devkit API files

This directory contains the minimal official API headers, module map and linker stub needed to build this project's RootHide variant with Xcode. It does not contain or install the `libroothide.dylib` runtime. That library is supplied by the device's `roothide` package, which is a dependency of the RootHide build.

## Sources

- `roothide.h` is an unchanged copy of `roothide-xcode.h` from [roothide/libroothide](https://github.com/roothide/libroothide/tree/cb236f9cf1c5e2ac932611328998a62b4b133e33), commit `cb236f9cf1c5e2ac932611328998a62b4b133e33`.
- `roothide/roothide.h`, `roothide/stub.h`, `roothide/module.modulemap` and `LICENSE` are unchanged copies from the same commit. The MIT license and RootHide copyright notice are retained.
- `roothide/libroothide.tbd` is copied, with only trailing whitespace removed, from [roothide/lib](https://github.com/roothide/lib/blob/85e9b5b8aff11bbefc59525c64c8f55149926e56/libroothide.tbd), commit `85e9b5b8aff11bbefc59525c64c8f55149926e56`. The original upstream SHA-256 is `f96b3b624f17dfd54ed59b05592ae3b0216adc9ac4ee2464348156ad017091c5`; the vendored file SHA-256 is `63e2ea4dd1501bd6b5a876f12c024f3643d5f13ee5147e89608ad1b3427e1e84`.

The linker stub declares arm64 and arm64e targets and the runtime install name `@loader_path/.jbroot/usr/lib/libroothide.dylib`. RootHide creates the required `.jbroot` links at installation or load time; no device-specific root path is included in this source tree or package.

## Integration

`make roothide` selects `packaging/roothide.xcconfig`, adds these include and library paths, defines `IH_ROOTHIDE=1`, and links `libroothide`. The original rootless build continues to use the separate libroot submodule. No Theos installation or RootHide Patcher conversion is needed.

See the official [developer instructions](https://github.com/roothide/Developer), [API documentation](https://github.com/roothide/Developer/blob/main/interface.md), [path and loader conventions](https://github.com/roothide/Developer/blob/main/roothide.md), and [entitlement requirements](https://github.com/roothide/Developer/blob/main/entitlements.md).
