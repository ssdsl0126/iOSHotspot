# iOSHotspot

[简体中文](README.md) · **English**

A hotspot management tool for jailbroken iPhones, with cellular, Wi-Fi and VPN upstream selection, automatic switching, traffic statistics and automatic shutoff rules.

Author: **newbie** · Package identifier: `com.newbie.ioshotspot`

## Requirements

- The minimum deployment target is **iOS 15.0**. The current release provides a rootless `iphoneos-arm64` package; use an installation tool appropriate for your jailbreak environment.
- This source adaptation adds a RootHide `iphoneos-arm64e` build. It requires a full jailbreak that supports module injection into `wifid`, `UserEventAgent` and `misd`. Standalone Bootstrap and environments that only support app injection are outside the supported scope.
- Use a device with a SIM card inserted and working cellular data. SIM-free use is outside the current supported scope.
- Connect the phone to the desired Wi-Fi network or VPN before selecting that upstream.
- The Control Center button requires **CCSupport** compatible with your iOS version. This optional button is not required to use the app.

Available functions depend on the device's runtime interfaces and the status shown in the app. The tool does not provide additional or free carrier data.

## Installation

1. Download the `.deb` package from [Releases](https://github.com/ssdsl0126/iOSHotspot/releases/latest).
2. Open and install it with a package manager such as Sileo or Zebra, and resolve dependencies when prompted. The package depends on `network-cmds` and `uikittools`; the RootHide build also depends on `roothide`. Build the adapted RootHide package from source using the instructions below.
3. After installation, open **iOSHotspot** from the Home Screen.

An iOSHotspot preference pane is also available in the Settings app. Its location may vary with your jailbreak and any tweak that groups preference panes.

## Start your first hotspot

The steps below include the Chinese labels used in the current app UI.

1. Open the app and turn on **启用 iOSHotspot** (Enable iOSHotspot).
2. Open **共享来源** (Sharing Source) and select an upstream. **蜂窝** (Cellular) is a good starting point.
3. Return to the main page, turn on **允许其他人加入** (Allow Others to Join), and wait for the hotspot to be shown as on.
4. Open **热点设置** (Hotspot Settings) to view the current network name and password. Tap the password to copy it, or scan the QR code from another device.
5. Check internet access on the connected device. To stop sharing, turn off **允许其他人加入**.

**启用 iOSHotspot** enables management by the tweak; **允许其他人加入** controls the hotspot itself. Disabling the tweak ends sharing managed by this project and rolls back its network changes.

## Choose an upstream

| Source | How to use it |
| --- | --- |
| Cellular (蜂窝) | Share the phone's cellular data connection. |
| Wi-Fi | Connect the phone to an upstream Wi-Fi network, then share that connection with hotspot clients. |
| VPN | Connect the VPN first, wait for its tunnel, addresses and routes to become ready, then start the hotspot. |
| Automatic (自动) | Follow available connections in this order: **connected VPN → connected Wi-Fi → cellular**. |

Automatic mode rebuilds the hotspot when switching upstreams, so clients may briefly disconnect. It will not restart the hotspot after you manually turn it off. With a fixed VPN source, the hotspot stops if the VPN disconnects or the primary tunnel changes, avoiding a switch to another network.

### VPN options

- **自动开启 VPN** (Automatically Connect VPN): when the source is fixed to **VPN**, requests a connection to the VPN currently selected by the system. Automatic source mode only follows existing connections and does not initiate VPN connections.
- **VPN IPv6 共享** (VPN IPv6 Sharing): off by default. To use it, stop the hotspot, confirm that IPv6 is enabled and working in the VPN with valid addresses and routes, enable this option, then restart the hotspot.

VPN IPv6 Sharing only controls the VPN source. IPv6 for cellular and Wi-Fi sources depends on the upstream network and system prefix advertisements. Clients may obtain IPv6 later than IPv4.

## Hotspot settings and management

- **最大兼容性** (Maximize Compatibility): follows the system Personal Hotspot setting and uses 2.4 GHz when enabled. Try it if a client cannot discover or connect to the hotspot. Changing it may briefly disconnect clients.
- **自动关闭** (Automatic Shutoff): stop sharing after a period with no clients, at a low battery threshold, or after reaching a daily traffic allowance. Rules are off by default. The daily allowance counts uploads and downloads together, resets on the phone's local date, and is entered in MiB.
- **Clients and statistics**: view current clients, give them local names, and inspect session, daily, 7-day and 30-day traffic. Statistics and client history stay on the phone for up to 30 days. The monthly figure is also limited by this retention period and is not a carrier billing measurement.
- **Settings preference pane**: provides common controls for hotspot status, tweak enablement, VPN options and copying diagnostics.

## Shortcuts

In Apple's Shortcuts app, add a **URL** action followed by **Open URLs**, and use one of these addresses:

| Action | URL |
| --- | --- |
| Start the hotspot | `ios-hotspot://start` |
| Stop the hotspot | `ios-hotspot://stop` |
| Toggle the hotspot | `ios-hotspot://toggle` |

You can also touch and hold the Home Screen app icon to start, stop or toggle the hotspot. With compatible CCSupport installed, add the iOSHotspot button through the system's Control Center editing interface.

## Troubleshooting

- **Backend unavailable or installation failed**: confirm that the jailbreak is active and dependencies are installed. Save the installation log, then reconfigure or reinstall the package with your package manager. Include the exact error if the problem persists.
- **Hotspot is on but clients cannot access the internet**: check the actual upstream and interface shown in the app. Confirm that the phone itself can use that connection, then reconnect the client.
- **A client has no IPv6 address**: confirm that the upstream has working IPv6, then allow time for prefix and router advertisements. For a VPN source, also enable VPN IPv6 Sharing. That option cannot create public IPv6 connectivity on an upstream that does not support it.
- **Control Center button is missing**: check that CCSupport supports your iOS version and is loaded, then look for iOSHotspot while editing Control Center.

To report a problem, select **复制诊断报告** (Copy Diagnostic Report) in the app's About page or Settings preference pane, then open an [issue](https://github.com/ssdsl0126/iOSHotspot/issues). Include your iOS version, jailbreak environment, sharing source and reproduction steps. Review the network information in the report before sharing it.

## Build from source (optional)

You need macOS, Xcode with its command-line tools, and working installations of `ldid`, `dpkg-deb` and Python 3. The project uses the official Xcode SDK and does not depend on Theos.

```sh
git clone --recurse-submodules https://github.com/ssdsl0126/iOSHotspot.git
cd iOSHotspot
make build
```

`make build` retains the original rootless build. To build the RootHide version:

```sh
make roothide
# Equivalent: make build IH_PACKAGE_SCHEME=roothide
```

The RootHide package is written to `build/release/com.newbie.ioshotspot_0.2.46+roothide1_iphoneos-arm64e.deb`. This entry point uses `packaging/roothide.xcconfig` and the official [RootHide devkit API files](third_party/roothide-devkit/README.md) included with the source. Theos and RootHide Patcher are not required. The optional Control Center entry still requires CCSupport compatible with your iOS version.

Alternatively, open `iOSHotspot.xcodeproj`, select the **iOSHotspot** scheme and an iOS device destination, and build; the default Xcode build remains rootless. All `.deb` files are written to `build/release/`. Dependencies reference their original repositories as submodules: [libroot](https://github.com/opa334/libroot) and [QR Code generator](https://github.com/nayuki/QR-Code-generator).

Validation of this RootHide adaptation is currently limited to local compilation and package inspection. Installation, actual injection into all three hosts, and cellular, Wi-Fi and VPN sharing behavior still require device testing.
