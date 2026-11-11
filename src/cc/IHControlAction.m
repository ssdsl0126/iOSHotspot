#import "IHControlAction.h"
#import "../common/IHProtocol.h"

NSDictionary *IHSetHotspotFromControlCenter(BOOL selected, NSError **error) {
    if (!selected) return IHRequest(@{@"command": @"stop"}, error);

    NSDictionary *status = IHRequest(@{@"command": @"status"}, error);
    if (![status[@"ok"] boolValue]) return status;
    if (![status[@"enabled"] isKindOfClass:NSNumber.class]) {
        return @{@"ok": @NO, @"error": @"无法确认 iOSHotspot 启用状态，未开启热点。"};
    }
    if (![status[@"enabled"] boolValue]) {
        // 走完整启用流程，保留当前来源、IPv6及自动关闭规则。
        NSDictionary *response = IHRequest(@{@"command": @"enable"}, error);
        if (![response[@"ok"] boolValue]) return response;
        if (![response[@"enabled"] isKindOfClass:NSNumber.class] || ![response[@"enabled"] boolValue]) {
            return @{@"ok": @NO, @"error": @"iOSHotspot 尚未启用，未开启热点。"};
        }
    }
    return IHRequest(@{@"command": @"start"}, error);
}
