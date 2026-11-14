#pragma once
#import <Foundation/Foundation.h>
#if IH_ROOTHIDE
#include <roothide.h>
#else
#include <libroot.h>
#endif
#ifndef IH_BUILD_VERSION
#define IH_BUILD_VERSION "development"
#endif

// 项目路径均从逻辑路径转换；系统框架、系统配置及设备节点仍使用原生路径。
static inline NSString *IHJailbreakPath(NSString *path) {
#if IH_ROOTHIDE
    return jbroot(path);
#else
    return JBROOT_PATH_NSSTRING(path);
#endif
}
#define IHDataDirectory IHJailbreakPath(@"/var/lib/com.newbie.ioshotspot")
#define IHRuntimeDirectory IHJailbreakPath(@"/var/run/com.newbie.ioshotspot")
#define IHLogDirectory IHJailbreakPath(@"/var/log/com.newbie.ioshotspot")
#define IHStorePath [IHDataDirectory stringByAppendingPathComponent:@"store.json"]
#define IHNetworkJournalPath [IHDataDirectory stringByAppendingPathComponent:@"network-journal.json"]
#define IHSourceRuntimePath [IHDataDirectory stringByAppendingPathComponent:@"source-runtime.json"]
#define IHNativeSessionPath [IHDataDirectory stringByAppendingPathComponent:@"vpn-native-session.json"]
#define IHNativeStatePath [IHDataDirectory stringByAppendingPathComponent:@"vpn-native-state.json"]
#define IHNativeJournalPath [IHDataDirectory stringByAppendingPathComponent:@"vpn-native-journal.json"]
#define IHSourceHookPath [IHRuntimeDirectory stringByAppendingPathComponent:@"source-hook.json"]
#define IHUSBSourceHookPath [IHRuntimeDirectory stringByAppendingPathComponent:@"source-usb-hook.json"]
#define IH16MisdState [IHRuntimeDirectory stringByAppendingPathComponent:@"named16-misd.json"]
#define IHWiFiPrefixStatePath [IHRuntimeDirectory stringByAppendingPathComponent:@"wifi-prefix.json"]
#define IHSocketPath [IHRuntimeDirectory stringByAppendingPathComponent:@"control.sock"]
#define IHServiceLogPath [IHLogDirectory stringByAppendingPathComponent:@"service.log"]
