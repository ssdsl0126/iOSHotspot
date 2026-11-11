#import <UIKit/UIKit.h>
#import <Preferences/PSListController.h>
#import <Preferences/PSSpecifier.h>
#import <notify.h>
#import "../common/IHProtocol.h"
#import "../common/IHHotspotCompatibility.h"

static BOOL IHPreferencesSupported(void) {
    return NSClassFromString(@"PSSpecifier") != Nil;
}

@interface IHRootController : PSListController
@property(nonatomic, strong) NSDictionary *actualStatus;
@property(nonatomic, strong) NSMutableArray *cachedSpecifiers;
@property(nonatomic, copy) NSString *statusError;
@property(nonatomic, strong) dispatch_queue_t requestQueue;
@property(nonatomic, strong) PSSpecifier *enabledSpecifier;
@property(nonatomic, strong) PSSpecifier *compatibilitySpecifier;
@property(nonatomic, strong) NSDictionary *compatibilityState;
@property(nonatomic, strong) PSSpecifier *vpnIPv6Specifier;
@property(nonatomic, strong) PSSpecifier *autoVPNSpecifier;
@property(nonatomic) BOOL reading;
@property(nonatomic) BOOL refreshPending;
@property(nonatomic) BOOL changing;
@property(nonatomic) BOOL visible;
@property(nonatomic) int notificationToken;
@end

@implementation IHRootController
- (instancetype)init {
    self = [super init];
    if (self) {
        _notificationToken = -1;
        _actualStatus = @{};
        _compatibilityState = @{};
        [IHHotspotCompatibility shared];
        _requestQueue = dispatch_queue_create("com.newbie.ioshotspot.preferences.ipc", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}
- (void)dealloc {
    if (_notificationToken >= 0) notify_cancel(_notificationToken);
}
- (NSMutableArray *)specifiers {
    if (!IHPreferencesSupported()) return [NSMutableArray new];
    if (self.cachedSpecifiers) return self.cachedSpecifiers;
    self.title = @"iOSHotspot";
    NSMutableArray *rows = [NSMutableArray new];
    PSSpecifier *group = [PSSpecifier groupSpecifierWithName:@"热点管理"];
    [group setProperty:@"完整实时状态、客户端、二维码和自动关闭规则位于主屏幕应用。" forKey:@"footerText"];
    [rows addObject:group];
    PSSpecifier *state = [PSSpecifier preferenceSpecifierNamed:@"热点状态" target:self set:NULL get:@selector(readHotspotState:) detail:Nil cell:PSTitleValueCell edit:Nil];
    [state setProperty:@"hotspotStatus" forKey:@"id"];
    [rows addObject:state];
    self.enabledSpecifier = [PSSpecifier preferenceSpecifierNamed:@"启用 iOSHotspot" target:self set:@selector(setProjectEnabled:specifier:) get:@selector(readProjectEnabled:) detail:Nil cell:PSSwitchCell edit:Nil];
    [self.enabledSpecifier setProperty:@([self.actualStatus[@"ok"] boolValue] && !self.changing) forKey:@"enabled"];
    [rows addObject:self.enabledSpecifier];
    [rows addObject:[self button:@"打开 iOSHotspot" action:@selector(openApplication)]];
    PSSpecifier *compatibilityGroup = [PSSpecifier groupSpecifierWithName:@"热点兼容性"];
    NSString *compatibilityDescription = @"与系统个人热点保持同步。开启后使用 2.4 GHz；切换时客户端可能短暂断开。";
    if (self.compatibilityState[@"error"]) compatibilityDescription = self.compatibilityState[@"error"];
    [compatibilityGroup setProperty:compatibilityDescription forKey:@"footerText"];
    [rows addObject:compatibilityGroup];
    self.compatibilitySpecifier = [PSSpecifier preferenceSpecifierNamed:@"最大兼容性" target:self set:@selector(setCompatibility:specifier:) get:@selector(readCompatibility:) detail:Nil cell:PSSwitchCell edit:Nil];
    [self.compatibilitySpecifier setProperty:@([self.compatibilityState[@"available"] boolValue] && !self.changing) forKey:@"enabled"];
    [rows addObject:self.compatibilitySpecifier];
    PSSpecifier *vpnGroup = [PSSpecifier groupSpecifierWithName:@"VPN 共享"];
    [vpnGroup setProperty:@"自动来源按 VPN、Wi-Fi、蜂窝的优先级跟随已有连接，不主动连接 VPN。自动开启 VPN 仅用于固定 VPN 来源。IPv6 更改前请先关闭热点。" forKey:@"footerText"];
    [rows addObject:vpnGroup];
    self.autoVPNSpecifier = [PSSpecifier preferenceSpecifierNamed:@"自动开启 VPN" target:self set:@selector(setAutoVPN:specifier:) get:@selector(readAutoVPN:) detail:Nil cell:PSSwitchCell edit:Nil];
    [self.autoVPNSpecifier setProperty:@([self.actualStatus[@"ok"] boolValue] && ([self.actualStatus[@"vpnAutoConnect"][@"supported"] boolValue] || [self.actualStatus[@"config"][@"autoVPN"] boolValue]) && ![self.actualStatus[@"source"] isEqual:@"auto"] && !self.changing) forKey:@"enabled"];
    [rows addObject:self.autoVPNSpecifier];
    self.vpnIPv6Specifier = [PSSpecifier preferenceSpecifierNamed:@"VPN IPv6 共享" target:self set:@selector(setVPNIPv6:specifier:) get:@selector(readVPNIPv6:) detail:Nil cell:PSSwitchCell edit:Nil];
    [self.vpnIPv6Specifier setProperty:@([self.actualStatus[@"ok"] boolValue] && !self.changing) forKey:@"enabled"];
    [rows addObject:self.vpnIPv6Specifier];
    PSSpecifier *about = [PSSpecifier groupSpecifierWithName:@"本地诊断"];
    [about setProperty:@"诊断在手机本地生成，仅复制到剪贴板，不会自动发送。停用会回滚项目所做的网络更改。" forKey:@"footerText"];
    [rows addObject:about];
    [rows addObject:[self button:@"复制诊断报告" action:@selector(copyReport)]];
    // 系统表格使用其原生列表存储；通过具名setter同步，不访问私有实例字段。
    [super setSpecifiers:rows];
    self.cachedSpecifiers = rows;
    return rows;
}
- (void)reloadSpecifiers {
    // 跟随系统列表刷新使项目缓存失效。
    self.cachedSpecifiers = nil;
    [super reloadSpecifiers];
}
- (PSSpecifier *)button:(NSString *)title action:(SEL)selector {
    PSSpecifier *specifier = [PSSpecifier preferenceSpecifierNamed:title target:self set:NULL get:NULL detail:Nil cell:PSButtonCell edit:Nil];
    specifier.buttonAction = selector;
    return specifier;
}
- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    if (!IHPreferencesSupported()) return;
    self.visible = YES;
    __weak IHRootController *weakSelf = self;
    if (self.notificationToken < 0) {
        int token = -1;
        int result = notify_register_dispatch("com.newbie.ioshotspot.changed", &token, dispatch_get_main_queue(), ^(int unused) {
            IHRootController *controller = weakSelf;
            if (controller.visible) [controller reloadActualStatus];
        });
        if (result == NOTIFY_STATUS_OK) self.notificationToken = token;
    }
    [self reloadActualStatus];
}
- (void)viewDidDisappear:(BOOL)animated {
    [super viewDidDisappear:animated];
    self.visible = NO;
    if (self.notificationToken >= 0) {
        notify_cancel(self.notificationToken);
        self.notificationToken = -1;
    }
}
- (void)reloadActualStatus {
    if (!IHPreferencesSupported()) return;
    if (self.reading) { self.refreshPending = YES; return; }
    self.reading = YES;
    __weak IHRootController *weakSelf = self;
    dispatch_async(self.requestQueue, ^{
        NSError *error = nil;
        NSDictionary *status = IHRequest(@{@"command": @"status"}, &error);
        NSDictionary *compatibility = IHHotspotCompatibility.shared.state;
        dispatch_async(dispatch_get_main_queue(), ^{
            IHRootController *controller = weakSelf;
            if (!controller) return;
            controller.reading = NO;
            controller.compatibilityState = compatibility;
            if ([status[@"ok"] boolValue]) {
                controller.actualStatus = status;
                controller.statusError = nil;
            } else {
                controller.actualStatus = @{};
                controller.statusError = [status[@"error"] isKindOfClass:NSString.class] ? status[@"error"] : (error.localizedDescription ?: @"后台服务不可用");
            }
            [controller.enabledSpecifier setProperty:@([status[@"ok"] boolValue] && !controller.changing) forKey:@"enabled"];
            [controller.autoVPNSpecifier setProperty:@([status[@"ok"] boolValue] && ([status[@"vpnAutoConnect"][@"supported"] boolValue] || [status[@"config"][@"autoVPN"] boolValue]) && ![status[@"source"] isEqual:@"auto"] && !controller.changing) forKey:@"enabled"];
            [controller.vpnIPv6Specifier setProperty:@([status[@"ok"] boolValue] && !controller.changing) forKey:@"enabled"];
            [controller.compatibilitySpecifier setProperty:@([compatibility[@"available"] boolValue] && !controller.changing) forKey:@"enabled"];
            [controller.compatibilitySpecifier setProperty:compatibility[@"error"] ?: @"" forKey:@"footerText"];
            [controller reloadSpecifiers];
            if (controller.refreshPending) {
                controller.refreshPending = NO;
                [controller reloadActualStatus];
            }
        });
    });
}
- (id)readHotspotState:(PSSpecifier *)specifier {
    if (!self.actualStatus[@"hotspotOn"]) return self.statusError.length ? @"后台服务不可用" : @"正在读取…";
    return [self.actualStatus[@"hotspotOn"] boolValue] ? @"已开启" : @"已关闭";
}
- (id)readProjectEnabled:(PSSpecifier *)specifier {
    return @([self.actualStatus[@"enabled"] boolValue]);
}
- (void)setProjectEnabled:(id)value specifier:(PSSpecifier *)specifier {
    [self sendRequest:@{@"command": [value boolValue] ? @"enable" : @"disable"} completion:nil];
}
- (id)readCompatibility:(PSSpecifier *)specifier {
    return self.compatibilityState[@"enabled"];
}
- (id)readVPNIPv6:(PSSpecifier *)specifier {
    return self.actualStatus[@"config"][@"vpnIPv6"] ?: @NO;
}
- (id)readAutoVPN:(PSSpecifier *)specifier { return self.actualStatus[@"config"][@"autoVPN"] ?: @NO; }
- (void)setAutoVPN:(id)value specifier:(PSSpecifier *)specifier {
    [self sendRequest:@{@"command":@"configure", @"config":@{@"autoVPN":@([value boolValue])}} completion:nil];
}
- (void)setVPNIPv6:(id)value specifier:(PSSpecifier *)specifier {
    [self sendRequest:@{@"command": @"configure", @"config": @{@"vpnIPv6": @([value boolValue])}} completion:nil];
}
- (void)setCompatibility:(id)value specifier:(PSSpecifier *)specifier {
    if (self.changing) return;
    self.changing = YES;
    [self.compatibilitySpecifier setProperty:@NO forKey:@"enabled"];
    [self reloadSpecifiers];
    dispatch_async(self.requestQueue, ^{
        NSError *error = nil;
        NSDictionary *actual = [IHHotspotCompatibility.shared setEnabled:[value boolValue] error:&error];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.changing = NO;
            if (actual) self.compatibilityState = actual;
            else [self showError:error.localizedDescription ?: @"无法更改系统兼容性设置。"];
            [self reloadActualStatus];
        });
    });
}
- (void)showError:(NSString *)message {
    if (self.presentedViewController) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"iOSHotspot" message:message preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}
- (void)sendRequest:(NSDictionary *)request completion:(void (^)(NSDictionary *))completion {
    if (self.changing || !IHPreferencesSupported()) return;
    self.changing = YES;
    [self.enabledSpecifier setProperty:@NO forKey:@"enabled"];
    [self.autoVPNSpecifier setProperty:@NO forKey:@"enabled"];
    [self.vpnIPv6Specifier setProperty:@NO forKey:@"enabled"];
    [self reloadSpecifiers];
    __weak IHRootController *weakSelf = self;
    dispatch_async(self.requestQueue, ^{
        NSError *error = nil;
        NSDictionary *response = IHRequest(request, &error);
        dispatch_async(dispatch_get_main_queue(), ^{
            IHRootController *controller = weakSelf;
            if (!controller) return;
            controller.changing = NO;
            if (![response[@"ok"] boolValue]) {
                NSString *message = [response[@"error"] isKindOfClass:NSString.class] ? response[@"error"] : (error.localizedDescription ?: @"后台服务未能完成操作。");
                [controller showError:message];
            } else if (completion) completion(response);
            [controller reloadActualStatus];
        });
    });
}
- (void)openApplication {
    [UIApplication.sharedApplication openURL:[NSURL URLWithString:@"ios-hotspot://status"] options:@{} completionHandler:^(BOOL success) {
        if (!success) [self showError:@"无法打开应用，请确认已安装 iOSHotspot 主屏幕应用。"];
    }];
}
- (void)copyReport {
    [self sendRequest:@{@"command": @"report"} completion:^(NSDictionary *response) {
        NSString *report = [response[@"report"] isKindOfClass:NSString.class] ? response[@"report"] : nil;
        if (!report.length) { [self showError:@"后台服务没有返回可用的诊断报告。"]; return; }
        UIPasteboard.generalPasteboard.string = report;
        [self showError:@"诊断报告已复制到本机剪贴板。"];
    }];
}
@end
