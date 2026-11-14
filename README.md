# iOSHotspot

**简体中文** · [English](README.en.md)

用于越狱 iPhone 的热点管理工具，提供蜂窝、Wi-Fi、VPN 共享来源选择、自动切换、流量统计和自动关闭规则。

作者：**newbie** · 包标识：`com.newbie.ioshotspot`

## 使用前准备

- 最低部署版本为 **iOS 15.0**；当前 Release 提供 rootless `iphoneos-arm64` 软件包，请使用与越狱环境匹配的安装工具。
- 本源码适配增加 RootHide `iphoneos-arm64e` 构建。需要能够向 `wifid`、`UserEventAgent` 和 `misd` 注入模块的完整越狱；独立 Bootstrap 或仅支持 App 注入的环境不在支持范围内。
- 请在已插入 SIM 卡、蜂窝数据可用的环境下使用。无卡场景不在当前适配范围内。
- 选择 Wi-Fi 或 VPN 来源时，先确保手机已经连接对应网络。
- 控制中心按钮需要安装兼容当前系统的 **CCSupport**；App 本身不依赖这个可选入口。

实际功能以设备上的接口能力和 App 提示为准。本工具不会提供额外或免费的运营商流量。

## 安装

1. 打开 [Releases](https://github.com/ssdsl0126/iOSHotspot/releases/latest)，下载 `.deb` 安装包。
2. 使用 Sileo、Zebra 等包管理器打开并安装，按提示处理依赖。软件包依赖 `network-cmds` 和 `uikittools`；RootHide 构建还依赖 `roothide`。RootHide 适配包可按下方说明从源码构建。
3. 安装完成后，从主屏幕打开 **iOSHotspot**。

系统设置中也有 iOSHotspot 的插件设置入口；具体分组位置可能随设置分组插件和越狱环境变化。

## 第一次开启热点

1. 打开 App，开启 **启用 iOSHotspot**。
2. 进入 **共享来源**，选择要共享的网络。初次使用建议先选 **蜂窝**。
3. 返回主页，开启 **允许其他人加入**，等待页面显示热点已开启。
4. 打开 **热点设置**，查看当前网络名称和密码，点击密码即可复制，也可以让另一台设备扫描二维码加入。
5. 在连接热点的设备上确认能够联网。结束共享时，关闭 **允许其他人加入**。

**启用 iOSHotspot** 用于启用插件管理；**允许其他人加入** 控制热点开关。停用插件会结束由本项目管理的共享并回滚相应网络更改。

## 选择共享来源

| 来源 | 使用方式 |
| --- | --- |
| 蜂窝 | 通过手机的蜂窝数据上网。 |
| Wi-Fi | 先让手机连接上游 Wi-Fi，再将该网络共享给热点客户端。 |
| VPN | 先连接 VPN，等待隧道、地址和路由就绪，再开启热点。 |
| 自动 | 按 **已连接 VPN → 已连接 Wi-Fi → 蜂窝** 的优先级跟随当前连接。 |

自动模式切换来源时会重建热点，客户端可能短暂断开。手动关闭热点后，自动模式不会自行重开。固定 VPN 来源下，VPN 断开或主隧道变化时会关闭热点，避免切换到其他网络。

### VPN 选项

- **自动开启 VPN**：用于固定选择 **VPN** 来源时，请求连接系统当前选中的 VPN；自动模式只跟随已有连接，不主动连接 VPN。
- **VPN IPv6 共享**：默认关闭。需要使用时，先关闭热点，确认 VPN 本身已启用 IPv6且地址、路由可用，再开启此选项并重新打开热点。

“VPN IPv6 共享”只控制 VPN 来源。蜂窝和 Wi-Fi 来源的 IPv6 取决于上游网络与系统的前缀通告；客户端获取 IPv6 可能比 IPv4 慢一些。

## 热点设置与管理

- **最大兼容性**：与系统个人热点选项同步，开启后使用 2.4 GHz。部分设备无法搜索或连接热点时可以尝试，切换时客户端可能短暂断开。
- **自动关闭**：可按无客户端时长、低电量和每日流量额度关闭热点。规则默认关闭；每日额度按上传与下载总和计算，并按手机本地日期重置，输入单位为 MiB。
- **客户端与统计**：可查看当前连接、重命名客户端，以及查看会话、今日、最近 7 天和 30 天流量。统计和客户端历史保存在本机，最多保留 30 天；“本月”数据也受此保留期限限制，读数不等于运营商账单。
- **系统设置入口**：提供热点状态、插件启用、VPN 选项和复制诊断等常用操作。

## 快捷操作

在系统“快捷指令”中添加 **URL** 和 **打开 URL** 两个操作，填入对应地址：

| 操作 | URL |
| --- | --- |
| 开启热点 | `ios-hotspot://start` |
| 关闭热点 | `ios-hotspot://stop` |
| 切换热点 | `ios-hotspot://toggle` |

也可以长按主屏幕 App 图标，选择开启、关闭或切换热点。安装 CCSupport 后，可在系统提供的控制中心编辑界面中添加 iOSHotspot 按钮。

## 常见问题

- **后台服务不可用或安装失败**：确认越狱环境有效、依赖已安装，保存安装日志，并通过包管理器重新配置或重新安装。仍有问题时，请提供具体错误。
- **热点已开启但无法联网**：检查 App 的实际共享来源和上游接口，确认手机本身能通过该网络联网，再尝试让客户端重新连接。
- **客户端没有 IPv6**：先确认上游网络有可用 IPv6，等待前缀和路由通告完成后再检查。VPN 来源还需要开启“VPN IPv6 共享”；开启该选项不能为不支持 IPv6 的上游生成公网 IPv6。
- **控制中心找不到按钮**：确认 CCSupport 兼容当前系统并已加载，再进入控制中心的编辑界面查找 iOSHotspot。

需要反馈问题时，可在 App 的“关于”页或插件设置中选择 **复制诊断报告**，通过 [Issues](https://github.com/ssdsl0126/iOSHotspot/issues) 提交，并说明系统版本、越狱环境、共享来源和复现步骤。分享前请检查报告中的网络信息。

## 从源码构建（可选）

需要 macOS、Xcode 与命令行工具，以及可用的 `ldid`、`dpkg-deb` 和 Python 3。项目使用 Xcode 官方 SDK，不依赖 Theos。

```sh
git clone --recurse-submodules https://github.com/ssdsl0126/iOSHotspot.git
cd iOSHotspot
make build
```

`make build` 保持原有 rootless 构建。构建 RootHide 版本：

```sh
make roothide
# 等效入口：make build IH_PACKAGE_SCHEME=roothide
```

生成的 RootHide 包为 `build/release/com.newbie.ioshotspot_0.2.46+roothide1_iphoneos-arm64e.deb`。该入口使用 `packaging/roothide.xcconfig` 和随源码提供的官方 [RootHide devkit API 文件](third_party/roothide-devkit/README.md)，无需安装 Theos 或使用 RootHide Patcher。控制中心入口仍需另外安装兼容当前系统的 CCSupport。

也可打开 `iOSHotspot.xcodeproj`，选择 **iOSHotspot** scheme 和 iOS 真机目标进行构建；Xcode 默认构建 rootless 版本。所有 `.deb` 均输出到 `build/release/`。依赖通过子模块引用原仓库：[libroot](https://github.com/opa334/libroot)、[QR Code generator](https://github.com/nayuki/QR-Code-generator)。

RootHide 适配当前的验证范围限于本地编译与软件包检查；设备安装、三个宿主的实际注入，以及蜂窝、Wi-Fi 和 VPN 共享行为仍需真机验证。
