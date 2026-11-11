#pragma once
#import <Foundation/Foundation.h>

static inline BOOL IHSourceModeSupported(id source) {
    return [@[@"cellular", @"wifi", @"vpn", @"auto"] containsObject:source ?: @""];
}

// 自动模式只跟随已连接的网络，不主动连接VPN；VPN未就绪时也不降级。
static inline NSString *IHResolvedSource(NSString *source, BOOL vpnConnected, BOOL wifiConnected) {
    if (![source isEqual:@"auto"]) return source ?: @"cellular";
    return vpnConnected ? @"vpn" : wifiConnected ? @"wifi" : @"cellular";
}
