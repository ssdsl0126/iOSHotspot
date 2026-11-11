#!/bin/zsh
set -euo pipefail
cd "${0:A:h:h}"
for dependency in third_party/libroot/src/dyn.c third_party/qrcodegen/c/qrcodegen.c; do
 [[ -f "$dependency" ]] || { print -u2 '请先执行 git submodule update --init --recursive'; exit 1; }
done
exec xcodebuild -project iOSHotspot.xcodeproj -scheme iOSHotspot -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' -derivedDataPath "$PWD/build/DerivedData" CODE_SIGNING_ALLOWED=NO build
