#import <Foundation/Foundation.h>
#import "../common/IHKernelVPN.h"
#import "../common/IHTimeouts.h"
#include <dlfcn.h>
#include <objc/message.h>

// 参考BetterCCVPN公开的系统偏好接口，独立实现当前选择的连接；不新建或修改VPN配置。
static int IHReply(NSDictionary *value) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:value options:0 error:nil];
    fwrite(data.bytes, 1, data.length, stdout); putchar('\n'); fflush(stdout);
    return [value[@"ok"] boolValue] ? 0 : 2;
}
static int IHFail(NSString *message) { return IHReply(@{@"ok":@NO, @"error":message}); }
static id IHObject(id object, NSString *name) {
    SEL selector = NSSelectorFromString(name);
    return [object respondsToSelector:selector] ? ((id (*)(id, SEL))objc_msgSend)(object, selector) : nil;
}
static void IHPump(void) { [NSRunLoop.currentRunLoop runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:.05]]; }
int main(int argc, char **argv) { @autoreleasepool {
    BOOL checking = argc == 2 && !strcmp(argv[1], "--check");
    if (argc != 2 || (!checking && strcmp(argv[1], "--connect"))) return 2;
    double overallDeadline = IHMonotonicTime() + 14;
    if (!dlopen("/System/Library/PreferenceBundles/VPNPreferences.bundle/VPNPreferences", RTLD_NOW | RTLD_LOCAL)) return IHFail(@"系统VPN控制接口不可用，请手动连接VPN。");
    @try {
        Class controllerClass = NSClassFromString(@"VPNController") ?: NSClassFromString(@"VPNNEController"), storeClass = NSClassFromString(@"VPNConnectionStore");
        SEL shared = NSSelectorFromString(@"sharedInstance"), active = NSSelectorFromString(@"activeVPNIDWithGrade:");
        if (!controllerClass || ![storeClass respondsToSelector:shared]) return IHFail(@"系统VPN控制类不可用，请手动连接VPN。");
        id controller = [[controllerClass alloc] init];
        id store = ((id (*)(id, SEL))objc_msgSend)(storeClass, shared);
        SEL specifiers = NSSelectorFromString(@"specifiers");
        if (!controller || ![store respondsToSelector:active] || ![controller respondsToSelector:specifiers]) return IHFail(@"系统VPN控制接口不完整，请手动连接VPN。");
        ((id (*)(id, SEL))objc_msgSend)(controller, specifiers);
        NSMutableDictionary<NSNumber *, NSUUID *> *selected = [NSMutableDictionary new];
        double loadedDeadline = IHMonotonicTime() + 2;
        do {
            [selected removeAllObjects];
            for (NSUInteger grade = 0; grade < 4; grade++) {
                id value = ((id (*)(id, SEL, NSUInteger))objc_msgSend)(store, active, grade);
                if ([value isKindOfClass:NSUUID.class]) selected[@(grade)] = value;
            }
            if (selected.count) break;
            IHPump();
        } while (IHMonotonicTime() < loadedDeadline);
        if (checking) return IHReply(@{@"ok":@YES, @"selectedCount":@(selected.count)});
        if (selected.count == 0) return IHFail(@"没有选中的系统VPN，请先在系统设置中选择VPN配置。");
        if (selected.count != 1) return IHFail(@"系统同时选择了多个类别的VPN，无法确定自动连接目标，请手动连接所需VPN。");
        NSNumber *grade = selected.allKeys.firstObject;
        NSString *identifier = selected[grade].UUIDString;
        // 系统选择标识是配置UUID，configd主服务使用协议UUID，二者不能直接比较。
        id manager = IHObject(NSClassFromString(@"NEConfigurationManager"), @"sharedManagerForAllUsers");
        SEL load = NSSelectorFromString(@"loadConfigurationsWithCompletionQueue:handler:");
        if (![manager respondsToSelector:load]) return IHFail(@"无法读取当前VPN的系统服务标识，请手动连接。");
        __block NSArray *configurations = nil; __block BOOL loaded = NO; __block NSError *loadError = nil;
        ((void (*)(id, SEL, dispatch_queue_t, id))objc_msgSend)(manager, load, dispatch_get_main_queue(), [^(NSArray *values, NSError *error) { configurations = values; loadError = error; loaded = YES; } copy]);
        double configurationDeadline = MIN(overallDeadline, IHMonotonicTime() + 2);
        while (!loaded && IHMonotonicTime() < configurationDeadline) IHPump();
        if (!loaded || loadError) return IHFail(@"当前VPN配置读取失败，请手动连接VPN。");
        NSUUID *protocolIdentifier = nil;
        for (id configuration in configurations) {
            id configurationID = IHObject(configuration, @"identifier");
            if (![configurationID isKindOfClass:NSUUID.class] || ![[configurationID UUIDString] isEqual:identifier]) continue;
            id value = IHObject(IHObject(IHObject(configuration, @"VPN"), @"protocol"), @"identifier");
            if ([value isKindOfClass:NSUUID.class]) protocolIdentifier = value;
        }
        if (!protocolIdentifier) return IHFail(@"所选VPN没有可识别的系统服务，未发起连接。");
        NSString *serviceIdentifier = protocolIdentifier.UUIDString;
        SEL current = NSSelectorFromString(@"currentConnectionWithGrade:");
        if (grade.integerValue > 1 || ![store respondsToSelector:current]) return IHFail(@"当前选中的VPN类别无法自动连接，请手动连接。");
        id connection = ((id (*)(id, SEL, NSUInteger))objc_msgSend)(store, current, grade.unsignedIntegerValue);
        id connectionIdentifier = IHObject(connection, @"serviceID");
        if (![connectionIdentifier isKindOfClass:NSUUID.class] || ![[connectionIdentifier UUIDString] isEqual:identifier]) return IHFail(@"系统VPN选择已改变，未发起连接，请重新开启热点。");
        SEL connect = NSSelectorFromString(@"connect");
        NSMethodSignature *signature = [connection methodSignatureForSelector:connect];
        if (!connection || !signature || signature.numberOfArguments != 2) return IHFail(@"当前选中的VPN不支持系统连接接口，请手动连接。");
        NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature]; invocation.target = connection; invocation.selector = connect; [invocation invoke];
        double deadline = MIN(overallDeadline, IHMonotonicTime() + 12);
        do {
            id currentIdentifier = ((id (*)(id, SEL, NSUInteger))objc_msgSend)(store, active, grade.unsignedIntegerValue);
            if (![currentIdentifier isEqual:selected[grade]]) return IHFail(@"系统VPN选择已改变，热点保持关闭。");
            NSDictionary *binding = IHKernelVPNBinding();
            if ([binding[@"serviceID"] isKindOfClass:NSString.class] && [binding[@"serviceID"] caseInsensitiveCompare:serviceIdentifier] == NSOrderedSame) return IHReply(@{@"ok":@YES, @"selectedServiceID":serviceIdentifier});
            IHPump();
        } while (IHMonotonicTime() < deadline);
        return IHFail(@"系统VPN未在期限内连接就绪，热点保持关闭，请检查VPN连接。");
    } @catch (NSException *exception) {
        return IHFail(@"系统VPN控制调用失败，热点保持关闭，请手动连接VPN。");
    }
} }
