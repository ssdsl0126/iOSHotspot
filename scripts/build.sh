#!/bin/zsh
set -euo pipefail
cd "${0:A:h:h}"
for dependency in third_party/libroot/src/dyn.c third_party/qrcodegen/c/qrcodegen.c; do
 [[ -f "$dependency" ]] || { print -u2 '请先执行 git submodule update --init --recursive'; exit 1; }
done
SCHEME=${IH_PACKAGE_SCHEME:-rootless}
build_options=()
case "$SCHEME" in
 rootless) ;;
 roothide)
  for dependency in third_party/roothide-devkit/roothide/roothide.h third_party/roothide-devkit/roothide/libroothide.tbd; do
   [[ -f "$dependency" ]] || { print -u2 "缺少 RootHide SDK 文件：$dependency"; exit 1; }
  done
  build_options=(-xcconfig "$PWD/packaging/roothide.xcconfig")
  ;;
 *) print -u2 "不支持的软件包方案：$SCHEME（可选 rootless、roothide）"; exit 1 ;;
esac
exec xcodebuild -project iOSHotspot.xcodeproj -scheme iOSHotspot -configuration Release -sdk iphoneos -destination 'generic/platform=iOS' -derivedDataPath "$PWD/build/DerivedData-$SCHEME" "${build_options[@]}" IH_PACKAGE_SCHEME="$SCHEME" CODE_SIGNING_ALLOWED=NO build
