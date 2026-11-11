#!/bin/zsh
set -euo pipefail
cd "${0:A:h:h}"
# Xcode从图形界面启动时可能不继承终端环境，补充独立签名和打包工具路径。
export PATH="/opt/procursus/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
PRODUCTS=${1:?需要Xcode构建产物目录}
OUTPUT=${2:-"$PWD/build/release"}
STAGE="$OUTPUT/stage"
SIGNER="${IH_SIGNER:-$(command -v ldid)}"
VERSION=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' packaging/app-Info.plist)
[[ "$VERSION" == "$(awk '/^Version: / { print $2 }' packaging/control)" ]]
mkdir -p "$OUTPUT"
rm -rf "$STAGE"
mkdir -p "$STAGE/var/jb/"{usr/libexec,Applications,Library/LaunchDaemons,Library/ControlCenter/Bundles,Library/PreferenceBundles,Library/PreferenceLoader/Preferences,Library/MobileSubstrate/DynamicLibraries}
# Xcode负责全部编译；这里只布局越狱文件、写入权限并封装deb。
cp -R "$PRODUCTS/iOSHotspot.app" "$STAGE/var/jb/Applications/"
cp -R "$PRODUCTS/iOSHotspotCC.bundle" "$STAGE/var/jb/Library/ControlCenter/Bundles/"
cp -R "$PRODUCTS/iOSHotspotPrefs.bundle" "$STAGE/var/jb/Library/PreferenceBundles/"
for helper in ioshotspotd ioshotspot-vpn16 ioshotspot-vpn-connect ioshotspot-paths ioshotspot-ui-refresh; do
 cp "$PRODUCTS/$helper" "$STAGE/var/jb/usr/libexec/$helper"
done
for library in iOSHotspotSource iOSHotspotNamed16Misd iOSHotspotNamed16Provider; do
 cp "$PRODUCTS/$library.dylib" "$STAGE/var/jb/Library/MobileSubstrate/DynamicLibraries/"
 case $library in
  iOSHotspotSource) filter=SourceHook ;;
  iOSHotspotNamed16Misd) filter=Named16Misd ;;
  iOSHotspotNamed16Provider) filter=Named16Provider ;;
 esac
 cp "src/tweak/$filter.plist" "$STAGE/var/jb/Library/MobileSubstrate/DynamicLibraries/$library.plist"
 "$SIGNER" -S "$STAGE/var/jb/Library/MobileSubstrate/DynamicLibraries/$library.dylib"
done
cp packaging/daemon.plist "$STAGE/var/jb/Library/LaunchDaemons/com.newbie.ioshotspot.plist"
cp packaging/entry.plist "$STAGE/var/jb/Library/PreferenceLoader/Preferences/iOSHotspot.plist"
for bundle in "$STAGE/var/jb/Library/ControlCenter/Bundles/iOSHotspotCC.bundle" "$STAGE/var/jb/Library/PreferenceBundles/iOSHotspotPrefs.bundle"; do
 cp packaging/icons/SettingsIcon*.png "$bundle/"
 /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$bundle/Info.plist"
 "$SIGNER" -S "$bundle/${${bundle:t}%.bundle}"
done
python3 - "$STAGE" <<'LICENSE'
import pathlib,sys
stage=pathlib.Path(sys.argv[1]);source=pathlib.Path('third_party/qrcodegen/c/qrcodegen.c').read_text()
(stage/'var/jb/Applications/iOSHotspot.app/Acknowledgements.txt').write_text(source[:source.index('*/')+2]+'\n\n'+pathlib.Path('third_party/libroot/LICENSE.md').read_text())
LICENSE
"$SIGNER" -Spackaging/app-entitlements.plist "$STAGE/var/jb/Applications/iOSHotspot.app/iOSHotspot"
for helper in ioshotspotd ioshotspot-vpn16 ioshotspot-paths; do
 "$SIGNER" -Spackaging/daemon-entitlements.plist "$STAGE/var/jb/usr/libexec/$helper"
done
"$SIGNER" -Spackaging/vpn-connect-entitlements.plist "$STAGE/var/jb/usr/libexec/ioshotspot-vpn-connect"
"$SIGNER" -S "$STAGE/var/jb/usr/libexec/ioshotspot-ui-refresh"
mkdir -p "$STAGE/DEBIAN"
cp packaging/{control,preinst,postinst,prerm} "$STAGE/DEBIAN/"
chmod 755 "$STAGE/DEBIAN/"{preinst,postinst,prerm}
PACKAGE="$OUTPUT/com.newbie.ioshotspot_${VERSION}_iphoneos-arm64.deb"
dpkg-deb --root-owner-group -b "$STAGE" "$PACKAGE"
shasum -a 256 "$PACKAGE"
