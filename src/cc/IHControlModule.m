#import <UIKit/UIKit.h>
#import <ControlCenterUIKit/CCUIToggleModule.h>
#import <notify.h>
#import "../common/IHProtocol.h"
#import "IHControlAction.h"

// 此 bundle 由 CCSupport 按需加载，不注入额外的 SpringBoard tweak。
@interface IHControlModule : CCUIToggleModule
@property(nonatomic) BOOL actualSelected;
@property(nonatomic) BOOL reading;
@property(nonatomic) BOOL refreshPending;
@property(nonatomic) BOOL changing;
@property(nonatomic) int notificationToken;
@property(nonatomic, strong) dispatch_queue_t requestQueue;
@end

@implementation IHControlModule
- (instancetype)init {
    self = [super init];
    if (self) {
        _notificationToken = -1;
        _requestQueue = dispatch_queue_create("com.newbie.ioshotspot.cc.ipc", DISPATCH_QUEUE_SERIAL);
        __weak IHControlModule *weakSelf = self;
        int result = notify_register_dispatch("com.newbie.ioshotspot.changed", &_notificationToken, dispatch_get_main_queue(), ^(int token) {
            [weakSelf reloadActualState];
        });
        if (result != NOTIFY_STATUS_OK) _notificationToken = -1;
        dispatch_async(dispatch_get_main_queue(), ^{ [weakSelf reloadActualState]; });
    }
    return self;
}
- (void)dealloc {
    if (_notificationToken >= 0) notify_cancel(_notificationToken);
}
- (UIImage *)iconGlyph {
    UIImageSymbolConfiguration *configuration = [UIImageSymbolConfiguration configurationWithPointSize:24 weight:UIImageSymbolWeightRegular];
    return [[UIImage systemImageNamed:@"personalhotspot" withConfiguration:configuration] imageWithRenderingMode:UIImageRenderingModeAlwaysTemplate];
}
- (UIImage *)selectedIconGlyph { return [self iconGlyph]; }
- (UIImage *)glyphImage { return [self iconGlyph]; }
- (UIColor *)selectedColor { return UIColor.systemGreenColor; }
- (BOOL)isSelected { return self.actualSelected; }
- (void)reloadActualState {
    if (self.reading) { self.refreshPending = YES; return; }
    self.reading = YES;
    __weak IHControlModule *weakSelf = self;
    dispatch_async(self.requestQueue, ^{
        NSError *error = nil;
        NSDictionary *status = IHRequest(@{@"command": @"status"}, &error);
        dispatch_async(dispatch_get_main_queue(), ^{
            IHControlModule *module = weakSelf;
            if (!module) return;
            module.reading = NO;
            if ([status[@"ok"] boolValue] && [status[@"hotspotOn"] isKindOfClass:NSNumber.class]) {
                module.actualSelected = [status[@"hotspotOn"] boolValue];
                [module refreshState];
            }
            if (module.refreshPending) {
                module.refreshPending = NO;
                [module reloadActualState];
            }
        });
    });
}
- (void)setSelected:(BOOL)selected {
    // 不提前点亮开关；重复点击也不翻转重试，只执行明确的开启或关闭。
    if (!self.requestQueue || self.changing) return;
    self.changing = YES;
    __weak IHControlModule *weakSelf = self;
    dispatch_async(self.requestQueue, ^{
        NSError *error = nil;
        NSDictionary *response = IHSetHotspotFromControlCenter(selected, &error);
        NSDictionary *status = IHRequest(@{@"command": @"status"}, NULL);
        BOOL failed = ![response[@"ok"] boolValue] || ![status[@"ok"] boolValue];
        dispatch_async(dispatch_get_main_queue(), ^{
            IHControlModule *module = weakSelf;
            if (!module) return;
            module.changing = NO;
            if ([status[@"ok"] boolValue] && [status[@"hotspotOn"] isKindOfClass:NSNumber.class]) module.actualSelected = [status[@"hotspotOn"] boolValue];
            [module refreshState];
            if (failed) {
                // 只打开应用查看后台返回的真实错误，不再次发起热点切换。
                [UIApplication.sharedApplication openURL:[NSURL URLWithString:@"ios-hotspot://status"] options:@{} completionHandler:nil];
            }
        });
    });
}
@end
