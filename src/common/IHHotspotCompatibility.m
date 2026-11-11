#import "IHHotspotCompatibility.h"
#include <dlfcn.h>

@implementation IHHotspotCompatibility {
    CFTypeRef _manager;
    CFTypeRef (*_copyProperty)(CFTypeRef, CFStringRef);
    void (*_setProperty)(CFTypeRef, CFStringRef, CFTypeRef);
    int (*_discoveryState)(CFTypeRef);
    void (*_setDiscovery)(CFTypeRef, CFDictionaryRef);
    void (*_unschedule)(CFTypeRef, CFRunLoopRef, CFStringRef);
}
+ (instancetype)shared {
    static IHHotspotCompatibility *instance;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ instance = [IHHotspotCompatibility new]; });
    return instance;
}
- (instancetype)init {
    if ((self = [super init])) {
        void *library = dlopen("/System/Library/PrivateFrameworks/MobileWiFi.framework/MobileWiFi", RTLD_NOW);
        if (!library) return self;
        CFTypeRef (*create)(CFAllocatorRef, int) = dlsym(library, "WiFiManagerClientCreate");
        void (*schedule)(CFTypeRef, CFRunLoopRef, CFStringRef) = dlsym(library, "WiFiManagerClientScheduleWithRunLoop");
        _copyProperty = dlsym(library, "WiFiManagerClientCopyProperty");
        _setProperty = dlsym(library, "WiFiManagerClientSetProperty");
        _discoveryState = dlsym(library, "WiFiManagerClientGetMISDiscoveryState");
        _setDiscovery = dlsym(library, "WiFiManagerClientSetMISDiscoveryStateExt");
        _unschedule = dlsym(library, "WiFiManagerClientUnscheduleFromRunLoop");
        if (create && schedule && _unschedule && _copyProperty && _setProperty && _discoveryState && _setDiscovery) {
            _manager = create(NULL, 0);
            if (_manager) schedule(_manager, CFRunLoopGetMain(), kCFRunLoopDefaultMode);
        }
    }
    return self;
}
- (void)dealloc {
    if (_manager) {
        _unschedule(_manager, CFRunLoopGetMain(), kCFRunLoopDefaultMode);
        CFRelease(_manager);
    }
}
- (NSDictionary *)state {
    @synchronized (self) {
        if (!_manager) return @{@"available": @NO, @"error": @"无法连接系统的热点设置服务。"};
        id value = _manager ? CFBridgingRelease(_copyProperty(_manager, CFSTR("phBandPreference"))) : nil;
        // 已核对系统bandPreference：未保存该属性时，intValue向nil取值为0，表示默认关闭。
        if (!value) return @{@"available": @YES, @"enabled": @NO, @"usesSystemDefault": @YES};
        if (![value isKindOfClass:NSNumber.class] || ([value integerValue] != 0 && [value integerValue] != 1)) {
            return @{@"available": @NO, @"error": @"无法读取系统的最大兼容性状态。"};
        }
        return @{@"available": @YES, @"enabled": @([value boolValue])};
    }
}
- (void)applyDiscovery:(int)discovery enabled:(BOOL)enabled {
    // Frida核实的原生选项组合；保留当前发现状态，不强开热点，不直接强制信道。
    NSMutableDictionary *options = [@{@"SOFTAP_ENABLE": @(discovery != 0), @"SOFTAP_IMMEDIATE_DISABLE": @YES} mutableCopy];
    if (enabled) options[@"SOFTAP_FORCE_2_4G_CHANNEL"] = @YES;
    _setDiscovery(_manager, (__bridge CFDictionaryRef)options);
}
- (NSDictionary *)setEnabled:(BOOL)enabled error:(NSError **)error {
    @synchronized (self) {
        NSDictionary *before = self.state;
        if (![before[@"available"] boolValue]) {
            if (error) *error = [NSError errorWithDomain:@"iOSHotspot.Compatibility" code:1 userInfo:@{NSLocalizedDescriptionKey: before[@"error"]}];
            return nil;
        }
        BOOL previous = [before[@"enabled"] boolValue];
        if (previous == enabled) return before;
        int discovery = _discoveryState(_manager);
        // 系统setter保存unsigned int；不要用CFBoolean替代原生数值类型。
        _setProperty(_manager, CFSTR("phBandPreference"), (__bridge CFTypeRef)@(enabled ? 1u : 0u));
        NSDictionary *actual = self.state;
        if ([actual[@"available"] boolValue] && [actual[@"enabled"] boolValue] == enabled) {
            [self applyDiscovery:discovery enabled:enabled];
            return actual;
        }
        _setProperty(_manager, CFSTR("phBandPreference"), (__bridge CFTypeRef)@(previous ? 1u : 0u));
        if (error) *error = [NSError errorWithDomain:@"iOSHotspot.Compatibility" code:2 userInfo:@{NSLocalizedDescriptionKey: @"系统没有确认兼容性设置，已恢复原选项。"}];
        return nil;
    }
}
@end
