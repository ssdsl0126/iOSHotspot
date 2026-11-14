#!/bin/zsh
set -euo pipefail
cd "${0:A:h:h}"
# Xcode从图形界面启动时可能不继承终端环境，补充独立签名和打包工具路径。
export PATH="/opt/procursus/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
PRODUCTS=${1:?需要Xcode构建产物目录}
OUTPUT=${2:-"$PWD/build/release"}
SCHEME=${IH_PACKAGE_SCHEME:-rootless}
case "$SCHEME" in
 rootless) PREFIX=/var/jb; ARCHITECTURE=iphoneos-arm64 ;;
 roothide) PREFIX=; ARCHITECTURE=iphoneos-arm64e ;;
 *) print -u2 "不支持的软件包方案：$SCHEME"; exit 1 ;;
esac
STAGE="$OUTPUT/stage-$SCHEME"
PAYLOAD="$STAGE$PREFIX"
SIGNER="${IH_SIGNER:-$(command -v ldid)}"
VERSION=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' packaging/app-Info.plist)
[[ "$VERSION" == "$(awk '/^Version: / { print $2 }' packaging/control)" ]]
DEB_VERSION="$VERSION"
[[ "$SCHEME" != roothide ]] || DEB_VERSION="$VERSION+roothide1"
# 拒绝给另一构建方案的产物改标签，避免生成可安装但路径 API 错误的软件包。
python3 - "$PRODUCTS" "$SCHEME" <<'VARIANT'
import pathlib, subprocess, sys
products, scheme = pathlib.Path(sys.argv[1]), sys.argv[2]
binaries = ['iOSHotspot.app/iOSHotspot', 'iOSHotspotCC.bundle/iOSHotspotCC',
            'iOSHotspotPrefs.bundle/iOSHotspotPrefs', 'ioshotspotd', 'ioshotspot-vpn16',
            'ioshotspot-vpn-connect', 'ioshotspot-paths', 'iOSHotspotSource.dylib',
            'iOSHotspotNamed16Misd.dylib', 'iOSHotspotNamed16Provider.dylib']
for name in binaries:
    dependencies = subprocess.check_output(['xcrun', 'otool', '-arch', 'all', '-L', str(products / name)], text=True)
    uses_roothide = '@loader_path/.jbroot/usr/lib/libroothide.dylib' in dependencies
    if uses_roothide != (scheme == 'roothide'):
        sys.exit(f'{name}: 构建产物与 {scheme} 打包方案不匹配，请重新运行 make build 或 make roothide。')
VARIANT
mkdir -p "$OUTPUT"
rm -rf "$STAGE"
mkdir -p "$PAYLOAD/"{usr/libexec,Applications,Library/LaunchDaemons,Library/ControlCenter/Bundles,Library/PreferenceBundles,Library/PreferenceLoader/Preferences,Library/MobileSubstrate/DynamicLibraries}
# RootHide dpkg 负责安装时创建 .jbroot 链接，不把本机或设备的随机根写入软件包。
ENTITLEMENTS=$(mktemp -d "$OUTPUT/.entitlements-$SCHEME.XXXXXX")
trap 'rm -rf "$ENTITLEMENTS"' EXIT
python3 - "$SCHEME" "$ENTITLEMENTS" <<'SIGNING'
import pathlib, plistlib, sys
scheme, output = sys.argv[1], pathlib.Path(sys.argv[2])
for name in ('app', 'daemon', 'vpn-connect'):
    value = plistlib.loads(pathlib.Path(f'packaging/{name}-entitlements.plist').read_bytes())
    if scheme == 'roothide':
        for key in ('platform-application', 'com.apple.private.security.no-sandbox',
                    'com.apple.private.security.storage.AppBundles',
                    'com.apple.private.security.storage.AppDataContainers'):
            value[key] = True
    (output / f'{name}.plist').write_bytes(plistlib.dumps(value))
SIGNING
set_library_id() {
 if [[ "$SCHEME" == roothide ]]; then
  xcrun install_name_tool -id "@loader_path/.jbroot$1" "$PAYLOAD$1"
 fi
}
# Xcode负责全部编译；这里只布局越狱文件、写入权限并封装deb。
cp -R "$PRODUCTS/iOSHotspot.app" "$PAYLOAD/Applications/"
cp -R "$PRODUCTS/iOSHotspotCC.bundle" "$PAYLOAD/Library/ControlCenter/Bundles/"
cp -R "$PRODUCTS/iOSHotspotPrefs.bundle" "$PAYLOAD/Library/PreferenceBundles/"
for helper in ioshotspotd ioshotspot-vpn16 ioshotspot-vpn-connect ioshotspot-paths; do
 cp "$PRODUCTS/$helper" "$PAYLOAD/usr/libexec/$helper"
done
for library in iOSHotspotSource iOSHotspotNamed16Misd iOSHotspotNamed16Provider; do
 cp "$PRODUCTS/$library.dylib" "$PAYLOAD/Library/MobileSubstrate/DynamicLibraries/"
 case $library in
  iOSHotspotSource) filter=SourceHook ;;
  iOSHotspotNamed16Misd) filter=Named16Misd ;;
  iOSHotspotNamed16Provider) filter=Named16Provider ;;
 esac
 cp "src/tweak/$filter.plist" "$PAYLOAD/Library/MobileSubstrate/DynamicLibraries/$library.plist"
 set_library_id "/Library/MobileSubstrate/DynamicLibraries/$library.dylib"
 "$SIGNER" -S "$PAYLOAD/Library/MobileSubstrate/DynamicLibraries/$library.dylib"
done
cp packaging/daemon.plist "$PAYLOAD/Library/LaunchDaemons/com.newbie.ioshotspot.plist"
cp packaging/entry.plist "$PAYLOAD/Library/PreferenceLoader/Preferences/iOSHotspot.plist"
for bundle in "$PAYLOAD/Library/ControlCenter/Bundles/iOSHotspotCC.bundle" "$PAYLOAD/Library/PreferenceBundles/iOSHotspotPrefs.bundle"; do
 cp packaging/icons/SettingsIcon*.png "$bundle/"
 /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$bundle/Info.plist"
 binary="$bundle/${${bundle:t}%.bundle}"
 set_library_id "${binary#$PAYLOAD}"
 "$SIGNER" -S "$binary"
done
python3 - "$PAYLOAD" "$SCHEME" <<'LICENSE'
import pathlib,sys
stage=pathlib.Path(sys.argv[1]);source=pathlib.Path('third_party/qrcodegen/c/qrcodegen.c').read_text()
licenses = source[:source.index('*/')+2]+'\n\n'+pathlib.Path('third_party/libroot/LICENSE.md').read_text()
if sys.argv[2] == 'roothide':
    licenses += '\n\n' + pathlib.Path('third_party/roothide-devkit/LICENSE').read_text()
(stage/'Applications/iOSHotspot.app/Acknowledgements.txt').write_text(licenses)
LICENSE
"$SIGNER" -S"$ENTITLEMENTS/app.plist" "$PAYLOAD/Applications/iOSHotspot.app/iOSHotspot"
for helper in ioshotspotd ioshotspot-vpn16 ioshotspot-paths; do
 "$SIGNER" -S"$ENTITLEMENTS/daemon.plist" "$PAYLOAD/usr/libexec/$helper"
done
"$SIGNER" -S"$ENTITLEMENTS/vpn-connect.plist" "$PAYLOAD/usr/libexec/ioshotspot-vpn-connect"
mkdir -p "$STAGE/DEBIAN"
cp packaging/{control,preinst,postinst,prerm} "$STAGE/DEBIAN/"
python3 - "$STAGE/DEBIAN/control" "$ARCHITECTURE" "$DEB_VERSION" "$SCHEME" <<'CONTROL'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
lines = path.read_text().splitlines()
for index, line in enumerate(lines):
    if line.startswith('Architecture: '): lines[index] = 'Architecture: ' + sys.argv[2]
    if line.startswith('Version: '): lines[index] = 'Version: ' + sys.argv[3]
    if line.startswith('Depends: ') and sys.argv[4] == 'roothide': lines[index] += ', roothide'
path.write_text('\n'.join(lines) + '\n')
CONTROL
chmod 755 "$STAGE/DEBIAN/"{preinst,postinst,prerm}
PACKAGE="$OUTPUT/com.newbie.ioshotspot_${DEB_VERSION}_${ARCHITECTURE}.deb"
dpkg-deb --root-owner-group -b "$STAGE" "$PACKAGE"
shasum -a 256 "$PACKAGE"
