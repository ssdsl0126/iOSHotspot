#import <UIKit/UIKit.h>
#import "IHQRCode.h"
#import <QuartzCore/QuartzCore.h>
#include <math.h>
#include <notify.h>
#import "../common/IHProtocol.h"
#import "../common/IHHotspotCompatibility.h"
#import "../common/IHTimeouts.h"

static NSString *const IHStateChanged = @"IHStateChanged";

// 缺失读数显示破折号，绝不把未知状态显示成零。
static NSString *IHText(id value) {
    return [value isKindOfClass:NSString.class] ? value : @"";
}
static NSString *IHBytes(id value) {
    if (![value isKindOfClass:NSNumber.class]) return @"—";
    return [NSByteCountFormatter stringFromByteCount:[value longLongValue] countStyle:NSByteCountFormatterCountStyleBinary];
}
static NSString *IHSource(NSString *value) {
    if ([value isEqualToString:@"cellular"]) return @"蜂窝网络";
    if ([value isEqualToString:@"wifi"]) return @"Wi-Fi";
    if ([value isEqualToString:@"vpn"]) return @"VPN";
    if ([value isEqualToString:@"auto"]) return @"自动";
    return @"未知";
}
static NSString *IHTransport(NSString *value) {
    if (!value.length) return @"未知连接方式";
    if ([value.lowercaseString containsString:@"usb"]) return @"USB";
    if ([value.lowercaseString containsString:@"bluetooth"]) return @"Bluetooth";
    if ([value.lowercaseString containsString:@"wi"] || [value.lowercaseString containsString:@"airport"]) return @"Wi-Fi";
    return value;
}
static NSString *IHDate(id value) {
    if (![value isKindOfClass:NSNumber.class] || [value doubleValue] <= 0) return @"未知时间";
    NSDateFormatter *formatter = [NSDateFormatter new];
    formatter.dateStyle = NSDateFormatterMediumStyle;
    formatter.timeStyle = NSDateFormatterShortStyle;
    return [formatter stringFromDate:[NSDate dateWithTimeIntervalSince1970:[value doubleValue]]];
}
static NSString *IHDuration(id value, BOOL on) {
    if (!on) return @"未开启";
    if (![value isKindOfClass:NSNumber.class] || [value doubleValue] <= 0) return @"—";
    NSTimeInterval elapsed = MAX(0, NSDate.date.timeIntervalSince1970 - [value doubleValue]);
    NSUInteger seconds = (NSUInteger)elapsed;
    return [NSString stringWithFormat:@"%lu 小时 %lu 分 %lu 秒", (unsigned long)(seconds / 3600), (unsigned long)((seconds / 60) % 60), (unsigned long)(seconds % 60)];
}
static void IHAlert(UIViewController *presenter, NSString *title, NSString *message) {
    if (!presenter || presenter.presentedViewController) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:message preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    [presenter presentViewController:alert animated:YES completion:nil];
}

@interface IHStore : NSObject
@property(nonatomic, strong) NSDictionary *status;
@property(nonatomic, strong) NSDictionary *compatibility;
@property(nonatomic, copy) NSString *errorText;
@property(nonatomic) BOOL connected;
@property(nonatomic) BOOL reading;
@property(nonatomic) BOOL commandInFlight;
@property(nonatomic) BOOL refreshPending;
@property(nonatomic, strong) NSNumber *hotspotTarget;
@property(nonatomic) double hotspotDeadline;
@property(nonatomic) NSUInteger operationSerial;
@property(nonatomic) BOOL reconciling;
@property(nonatomic, copy) dispatch_block_t pendingCommand;
@property(nonatomic) BOOL compatibilityBusy;
@property(nonatomic) int notificationToken;
@property(nonatomic, strong) NSTimer *timer;
@property(nonatomic, strong) dispatch_queue_t queue;
@property(nonatomic, strong) dispatch_queue_t compatibilityQueue;
+ (instancetype)shared;
- (void)refresh;
- (void)activate;
- (void)deactivate;
- (void)send:(NSDictionary *)request presenter:(UIViewController *)presenter completion:(void (^)(NSDictionary *))completion;
@end

@implementation IHStore
+ (instancetype)shared {
    static IHStore *store;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        store = [IHStore new];
        store.status = @{};
        store.compatibility = @{};
        store.notificationToken = -1;
        [IHHotspotCompatibility shared];
        store.queue = dispatch_queue_create("com.newbie.ioshotspot.app.ipc", DISPATCH_QUEUE_SERIAL);
        store.compatibilityQueue = dispatch_queue_create("com.newbie.ioshotspot.app.compatibility", DISPATCH_QUEUE_SERIAL);
    });
    return store;
}
- (void)publish {
    [NSNotificationCenter.defaultCenter postNotificationName:IHStateChanged object:self];
}
- (void)refresh {
    [self expireHotspotTransition];
    [self refreshCompatibility];
    if (self.reading || self.commandInFlight) { self.refreshPending = YES; return; }
    self.refreshPending = NO;
    self.reading = YES;
    NSUInteger serial = self.operationSerial;
    dispatch_async(self.queue, ^{
        NSError *error = nil;
        NSDictionary *response = IHRequest(@{@"command": @"status"}, &error);
        dispatch_async(dispatch_get_main_queue(), ^{
            self.reading = NO;
            // 命令发出前或超时前的旧查询不能覆盖新一轮状态。
            if (serial != self.operationSerial) { [self refresh]; return; }
            self.connected = response && [response[@"ok"] boolValue];
            if (self.connected) {
                self.status = response;
                self.errorText = nil;
                self.reconciling = NO;
            } else {
                self.errorText = IHText(response[@"error"]);
                if (!self.errorText.length) self.errorText = error.localizedDescription ?: @"无法连接 iOSHotspot 后台服务。";
            }
            [self settleHotspotTransition];
            [self publish];
            if (self.refreshPending) [self refresh];
        });
    });
}
- (void)activate {
    [self deactivate];
    [self expireHotspotTransition];
    __weak IHStore *weak = self;
    if (notify_register_dispatch("com.newbie.ioshotspot.changed", &_notificationToken, dispatch_get_main_queue(), ^(int token) { [weak refresh]; }) != NOTIFY_STATUS_OK) self.notificationToken = -1;
    [self refresh];
    self.timer = [NSTimer scheduledTimerWithTimeInterval:2.0 target:self selector:@selector(refresh) userInfo:nil repeats:YES];
    self.timer.tolerance = 0.5;
}
- (void)deactivate {
    if (self.notificationToken >= 0) { notify_cancel(self.notificationToken); self.notificationToken = -1; }
    [self.timer invalidate];
    self.timer = nil;
}
- (void)settleHotspotTransition {
    [self expireHotspotTransition];
    if (!self.hotspotTarget || self.commandInFlight) return;
    BOOL target = self.hotspotTarget.boolValue;
    NSDictionary *vpn = self.status[@"vpnSharing"];
    NSString *automaticPhase = self.status[@"vpnAutoConnect"][@"phase"];
    if ([self.status[@"automaticSource"][@"phase"] isEqual:@"failed"]) automaticPhase = @"failed";
    BOOL ready = self.connected && [self.status[@"hotspotOn"] isKindOfClass:NSNumber.class] && [self.status[@"hotspotOn"] boolValue] == target;
    if (ready && target && [(self.status[@"effectiveSource"] ?: self.status[@"source"]) isEqual:@"vpn"]) ready = [vpn[@"phase"] isEqual:@"running"];
    if (ready || (self.connected && ([vpn[@"phase"] isEqual:@"failed"] || (target && [@[@"failed", @"cancelled"] containsObject:automaticPhase ?: @""])))) {
        self.hotspotTarget = nil; self.hotspotDeadline = 0;
    }
}
- (void)expireHotspotTransition {
    if ((!self.commandInFlight && !self.hotspotTarget) || self.hotspotDeadline <= 0 || IHMonotonicTime() < self.hotspotDeadline) return;
    // 独立于IPC、可选属性读取与成功回调；超时只结束等待，不假报热点已经关闭。
    self.operationSerial++;
    if (self.pendingCommand) dispatch_block_cancel(self.pendingCommand);
    self.pendingCommand = nil;
    self.commandInFlight = NO;
    self.hotspotTarget = nil; self.hotspotDeadline = 0;
    self.connected = NO; self.reconciling = YES;
    self.errorText = @"操作等待超时，尚未确认最终热点状态，请重新读取。";
    [self publish];
}
- (void)queryCompatibility:(NSNumber *)enabled presenter:(UIViewController *)presenter {
    if (self.compatibilityBusy) return;
    self.compatibilityBusy = YES;
    __block BOOL completed = NO;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        if (completed) return;
        // 不尝试强行终止系统调用；保持单次在途查询，热点IPC仍可独立工作。
        self.compatibility = @{@"available": @NO, @"error": @"系统兼容性设置响应超时。"};
        [self publish];
    });
    dispatch_async(self.compatibilityQueue, ^{
        NSError *error = nil;
        NSDictionary *actual = enabled ? [IHHotspotCompatibility.shared setEnabled:enabled.boolValue error:&error] : IHHotspotCompatibility.shared.state;
        dispatch_async(dispatch_get_main_queue(), ^{
            completed = YES; self.compatibilityBusy = NO;
            self.compatibility = actual ?: @{@"available": @NO, @"error": error.localizedDescription ?: @"无法读取兼容性设置。"};
            if (enabled && !actual) IHAlert(presenter, @"设置未完成", error.localizedDescription ?: @"无法更改系统兼容性设置。");
            [self publish];
        });
    });
}
- (void)refreshCompatibility { [self queryCompatibility:nil presenter:nil]; }
- (void)setCompatibility:(BOOL)enabled presenter:(UIViewController *)presenter {
    if (self.commandInFlight || self.hotspotTarget || self.compatibilityBusy) return;
    [self queryCompatibility:@(enabled) presenter:presenter];
}
- (void)send:(NSDictionary *)request presenter:(UIViewController *)presenter completion:(void (^)(NSDictionary *))completion {
    [self expireHotspotTransition];
    if (self.reconciling) {
        IHAlert(presenter, @"正在确认状态", @"上一次操作已超时，读取后台实际状态后才能继续操作。");
        [self refresh]; return;
    }
    if (self.commandInFlight || self.hotspotTarget) {
        IHAlert(presenter, @"正在处理", @"请等待当前操作完成。");
        return;
    }
    self.commandInFlight = YES;
    NSUInteger serial = ++self.operationSerial;
    self.hotspotDeadline = IHMonotonicTime() + IHHotspotTransitionTimeout;
    NSString *command = request[@"command"];
    if ([@[@"start", @"stop", @"toggle"] containsObject:command]) {
        self.hotspotTarget = [command isEqual:@"toggle"] ? @(![self.status[@"hotspotOn"] boolValue]) : @([command isEqual:@"start"]);
    }
    [self publish];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, IHHotspotTransitionTimeout * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        if (serial != self.operationSerial) return;
        [self expireHotspotTransition];
        if (self.reconciling) [self refresh];
    });
    self.pendingCommand = dispatch_block_create(0, ^{
        NSError *error = nil;
        NSDictionary *response = IHRequest(request, &error);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (serial != self.operationSerial) return;
            self.pendingCommand = nil;
            self.commandInFlight = NO;
            if (!response || ![response[@"ok"] boolValue]) {
                self.hotspotTarget = nil; self.hotspotDeadline = 0;
                NSString *message = IHText(response[@"error"]);
                if (!message.length) message = error.localizedDescription ?: @"后台服务未能完成操作。";
                IHAlert(presenter, @"操作未完成", message);
            } else {
                // 立即使用刚返回的真实状态，避免等下一次轮询才更新开关。
                if (response[@"hotspotOn"] && response[@"config"]) { self.status = response; self.connected = YES; self.errorText = nil; }
                [self settleHotspotTransition];
                if (completion) completion(response);
            }
            [self publish];
            [self refresh];
        });
    });
    dispatch_async(self.queue, self.pendingCommand);
}
@end

typedef NS_ENUM(NSInteger, IHPage) {
    IHPageDashboard, IHPageJoin, IHPageSource, IHPageRules, IHPageHistory, IHPageAbout, IHPageShortcuts
};

@interface IHViewController : UITableViewController
@property(nonatomic) IHPage page;
@property(nonatomic, strong) NSArray<NSArray<NSDictionary *> *> *sections;
@property(nonatomic, strong) NSArray<NSString *> *headers;
@property(nonatomic, strong) NSArray<NSString *> *footers;
@property(nonatomic, strong) UIImage *qrImage;
@property(nonatomic, copy) NSString *qrPayload;
- (instancetype)initWithPage:(IHPage)page;
- (void)performHotspotAction:(NSString *)action;
@end

@implementation IHViewController
- (instancetype)initWithPage:(IHPage)page {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) self.page = page;
    return self;
}
- (void)viewDidLoad {
    [super viewDidLoad];
    self.tableView.backgroundColor = UIColor.systemGroupedBackgroundColor;
    self.tableView.rowHeight = UITableViewAutomaticDimension;
    self.tableView.estimatedRowHeight = 58;
    self.navigationItem.largeTitleDisplayMode = UINavigationItemLargeTitleDisplayModeAlways;
    NSArray *titles = @[@"iOSHotspot", @"热点设置", @"共享来源", @"自动关闭", @"客户端历史", @"关于", @"快捷操作"];
    self.title = titles[self.page];
    if (self.page == IHPageDashboard) {
        self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithImage:[UIImage systemImageNamed:@"info.circle"] style:UIBarButtonItemStylePlain target:self action:@selector(showAbout)];
        self.navigationItem.rightBarButtonItem.accessibilityLabel = @"关于 iOSHotspot";
    }
    self.refreshControl = [UIRefreshControl new];
    [self.refreshControl addTarget:self action:@selector(manualRefresh) forControlEvents:UIControlEventValueChanged];
    [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(stateChanged) name:IHStateChanged object:nil];
    [self rebuild];
}
- (void)dealloc {
    [NSNotificationCenter.defaultCenter removeObserver:self];
}
- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self rebuild];
    [IHStore.shared refresh];
}
- (void)manualRefresh {
    [IHStore.shared refresh];
}
- (void)stateChanged {
    [self.refreshControl endRefreshing];
    // 仅刷新当前可见页面，避免后台页、弹窗及手势期间重载表格打断用户操作。
    if (!self.isViewLoaded || !self.view.window || self.presentedViewController || self.tableView.isTracking || self.tableView.isDecelerating) return;
    [self rebuild];
}
- (NSDictionary *)row:(NSString *)title value:(NSString *)value action:(NSString *)action {
    NSMutableDictionary *row = [@{@"title": title ?: @"", @"value": value ?: @""} mutableCopy];
    if (action) row[@"action"] = action;
    return row;
}
- (NSDictionary *)toggleRow:(NSString *)title value:(BOOL)value action:(NSString *)action {
    return @{@"title": title, @"switch": @(value), @"action": action};
}
- (NSDictionary *)compatibilityRow {
    NSDictionary *state = IHStore.shared.compatibility;
    if (![state[@"available"] boolValue]) return [self row:@"最大兼容性" value:IHText(state[@"error"]).length ? state[@"error"] : @"正在读取…" action:nil];
    return [self toggleRow:@"最大兼容性" value:[state[@"enabled"] boolValue] action:@"compatibility"];
}
- (NSDictionary *)trafficRow:(NSString *)title prefix:(NSString *)prefix status:(NSDictionary *)status {
    return [self row:title value:[NSString stringWithFormat:@"↓ %@    ↑ %@", IHBytes(status[[prefix stringByAppendingString:@"Rx"]]), IHBytes(status[[prefix stringByAppendingString:@"Tx"]])] action:nil];
}
- (NSArray *)safeArray:(id)value {
    if (![value isKindOfClass:NSArray.class]) return @[];
    NSMutableArray *result = [NSMutableArray new];
    for (id item in value) if ([item isKindOfClass:NSDictionary.class]) [result addObject:item];
    return result;
}
- (void)rebuild {
    IHStore *store = IHStore.shared;
    NSDictionary *status = store.status ?: @{};
    NSDictionary *config = [status[@"config"] isKindOfClass:NSDictionary.class] ? status[@"config"] : @{};
    NSMutableArray *sections = [NSMutableArray new], *headers = [NSMutableArray new], *footers = [NSMutableArray new];
    void (^add)(NSString *, NSArray *, NSString *) = ^(NSString *header, NSArray *rows, NSString *footer) {
        [headers addObject:header ?: @""]; [sections addObject:rows ?: @[]]; [footers addObject:footer ?: @""];
    };
    if (!store.connected) {
        add(@"后台服务不可用", @[[self row:@"无法取得实时状态" value:store.errorText ?: @"正在连接…" action:@"refresh"]], @"请确认软件包及后台服务已经安装。重新读取前不会显示缓存为实时数据。");
    } else if (self.page == IHPageDashboard) {
        BOOL enabled = [status[@"enabled"] boolValue];
        BOOL on = [status[@"hotspotOn"] boolValue];
        NSMutableArray *overview = [NSMutableArray arrayWithArray:@[
            [self toggleRow:@"启用 iOSHotspot" value:enabled action:@"enabled"],
            [self toggleRow:@"允许其他人加入" value:on action:@"hotspot"],
            [self row:@"开启时长" value:IHDuration(status[@"sessionStarted"], on) action:nil]
        ]];
        NSString *lastError = IHText(status[@"lastError"]);
        if ([status[@"vpnAutoConnect"][@"busy"] boolValue]) [overview addObject:[self row:@"VPN" value:@"正在连接系统选中的 VPN…" action:nil]];
        if (lastError.length) [overview addObject:[self row:@"最近状态" value:lastError action:nil]];
        NSString *heading = store.hotspotTarget ? (store.hotspotTarget.boolValue ? @"正在开启热点" : @"正在关闭热点") : (on ? @"热点已开启" : @"热点未开启");
        add(heading, overview, @"开关读取并控制系统个人热点。连接数量、流量和来源以后台服务读数为准。");
        NSArray *clients = [self safeArray:status[@"clients"]];
        NSMutableArray *clientRows = [NSMutableArray new];
        NSString *count = [status[@"clientCount"] isKindOfClass:NSNumber.class] ? [status[@"clientCount"] stringValue] : @"—";
        NSString *maximum = [status[@"maxClients"] isKindOfClass:NSNumber.class] ? [status[@"maxClients"] stringValue] : @"—";
        [clientRows addObject:[self row:@"已连接" value:[NSString stringWithFormat:@"%@ / %@", count, maximum] action:nil]];
        for (NSDictionary *client in clients) {
            if (client[@"connected"] && ![client[@"connected"] boolValue]) continue;
            NSString *name = IHText(client[@"name"]); if (!name.length) name = IHText(client[@"id"]);
            NSMutableDictionary *row = [[self row:name.length ? name : @"未命名设备" value:IHTransport(IHText(client[@"transport"])) action:@"rename"] mutableCopy];
            row[@"client"] = client; [clientRows addObject:row];
        }
        if (clientRows.count == 1) [clientRows addObject:[self row:@"暂无已识别客户端" value:@"" action:nil]];
        add(@"连接客户端", clientRows, @"点击设备可重命名。连接方式由系统记录识别，无法识别时会明确显示未知。");
        add(@"流量", @[
            [self trafficRow:@"当前会话" prefix:@"session" status:status],
            [self trafficRow:@"今日" prefix:@"today" status:status],
            [self trafficRow:@"本月" prefix:@"month" status:status],
            [self trafficRow:@"过去 7 天" prefix:@"sevenDays" status:status],
            [self trafficRow:@"过去 30 天" prefix:@"thirtyDays" status:status]
        ], @"↓ 下载到客户端，↑ 客户端上传。读数只代表热点计量，不代表运营商账单。");
        add(@"共享", @[
            [self row:@"共享来源" value:[status[@"source"] isEqual:@"auto"]?[NSString stringWithFormat:@"自动 · %@",IHSource(IHText(status[@"effectiveSource"]))]:IHSource(IHText(status[@"source"])) action:@"source"],
            [self row:@"上游接口" value:IHText(status[@"upstream"]).length ? IHText(status[@"upstream"]) : @"未建立" action:nil],
            [self row:@"热点设置" value:@"网络名称、密码、兼容性与二维码" action:@"join"]
        ], @"");
        add(@"管理", @[
            [self row:@"自动关闭" value:@"空闲、电量与每日额度" action:@"rules"],
            [self row:@"客户端历史" value:@"最近 30 天" action:@"history"],
            [self row:@"快捷操作" value:@"快捷指令与主屏幕" action:@"shortcuts"]
        ], @"");
    } else if (self.page == IHPageJoin) {
        NSString *ssid = IHText(status[@"ssid"]), *password = IHText(status[@"password"]);
        add(@"热点信息", @[
            [self row:@"网络名称" value:ssid.length ? ssid : @"无法读取" action:nil],
            [self row:@"Wi-Fi 密码" value:password.length ? password : @"无法读取" action:password.length ? @"copyPassword" : nil],
            [self compatibilityRow]
        ], @"点击密码即可复制到本机剪贴板。网络名称与密码来自手机当前真实配置。");
        if (ssid.length && password.length) {
            [self updateQRForSSID:ssid password:password];
            if(self.qrImage)add(@"扫码加入", @[@{@"title": @"", @"qr": @YES}], @"在另一台设备上扫描二维码。加入后还需确认该客户端可以实际联网。");
            else add(@"扫码加入", @[[self row:@"二维码不可用" value:@"请使用当前网络名称和密码加入。" action:nil]], @"");
        } else {
            add(@"扫码加入", @[[self row:@"二维码不可用" value:@"需要读取真实网络名称与密码。" action:nil]], @"");
        }
    } else if (self.page == IHPageSource) {
        NSString *source = IHText(status[@"source"]);
        NSArray *keys = @[@"auto", @"cellular", @"wifi", @"vpn"];
        NSArray *details = @[@"跟随当前连接，优先 VPN，其次 Wi-Fi，最后蜂窝", @"通过手机蜂窝网络转发", @"通过手机当前 Wi-Fi 上游转发", @"通过系统原生路由与已连接 VPN 共享"];
        NSMutableArray *rows = [NSMutableArray new];
        for (NSUInteger index = 0; index < keys.count; index++) {
            NSMutableDictionary *row = [[self row:IHSource(keys[index]) value:details[index] action:@"selectSource"] mutableCopy];
            row[@"source"] = keys[index]; row[@"checked"] = @([source isEqual:keys[index]]); [rows addObject:row];
        }
        add(@"选择上游", rows, @"后台服务会检查真实转发能力与连接状态；不支持或无法安全建立转发时会拒绝启用并显示原因。");
        add(@"当前状态", @[
            [self row:@"当前转发来源" value:IHSource(IHText(status[@"effectiveSource"] ?: source)) action:nil],
            [self row:@"上游接口" value:IHText(status[@"upstream"]).length ? IHText(status[@"upstream"]) : @"未建立" action:nil]
        ], [source isEqual:@"auto"]?@"优先使用已连接 VPN，其次是已连接 Wi-Fi，最后是蜂窝。来源变化时会重建热点，客户端可能短暂断开；手动关闭后不会自行重开。":@"VPN 就绪后才启动共享。断开或主隧道改变后会关闭热点，避免回落到其他网络。");
        NSMutableDictionary *automatic = [[self toggleRow:@"自动开启 VPN" value:[config[@"autoVPN"] boolValue] action:@"autoVPN"] mutableCopy];
        automatic[@"disabled"] = @([source isEqual:@"auto"] || (![status[@"vpnAutoConnect"][@"supported"] boolValue] && ![config[@"autoVPN"] boolValue]));
        add(@"VPN 设置", @[automatic, [self toggleRow:@"VPN IPv6 共享" value:[config[@"vpnIPv6"] boolValue] action:@"vpnIPv6"]], @"自动模式只跟随已有连接，不主动连接 VPN。“自动开启 VPN”用于固定 VPN 来源。IPv6 共享默认关闭，更改前请先关闭 VPN 热点。");
    } else if (self.page == IHPageRules) {
        NSInteger idle = [config[@"idleMinutes"] integerValue];
        NSInteger battery = [config[@"lowBatteryPercent"] integerValue];
        unsigned long long limit = [config[@"dailyLimitBytes"] unsignedLongLongValue];
        add(@"关闭条件", @[
            [self row:@"无客户端时" value:idle > 0 ? [NSString stringWithFormat:@"%ld 分钟后关闭", (long)idle] : @"关闭此规则" action:@"idle"],
            [self row:@"低电量时" value:battery > 0 ? [NSString stringWithFormat:@"不高于 %ld%%", (long)battery] : @"关闭此规则" action:@"battery"],
            [self row:@"每日流量额度" value:limit > 0 ? IHBytes(@(limit)) : @"不设额度" action:@"limit"]
        ], @"配置交由后台服务保存并执行。每日额度统计上传与下载总和，按手机本地日期重置。");
        add(@"规则说明", @[[self row:@"自动关闭作用于手机热点" value:@"无客户端规则从最后一个客户端断开开始计时；低电量与每日额度达到阈值时关闭热点。" action:nil]], @"");
    } else if (self.page == IHPageHistory) {
        NSArray *history = [self safeArray:status[@"history"]];
        NSMutableArray *rows = [NSMutableArray new];
        for (NSDictionary *client in history) {
            NSString *name = IHText(client[@"name"]); if (!name.length) name = IHText(client[@"id"]);
            NSString *detail = [NSString stringWithFormat:@"%@ · %@%@", IHTransport(IHText(client[@"transport"])), IHDate(client[@"lastSeen"]), [client[@"connected"] boolValue] ? @" · 已连接" : @""];
            NSMutableDictionary *row = [[self row:name.length ? name : @"未命名设备" value:detail action:@"rename"] mutableCopy]; row[@"client"] = client; [rows addObject:row];
        }
        if (!rows.count) [rows addObject:[self row:@"暂无客户端历史" value:@"连接真实设备后会在此显示。" action:nil]];
        add(@"最近 30 天", rows, @"点击设备可重命名。历史及名称只保存在手机，可在关于页面清除。");
    } else if (self.page == IHPageAbout) {
        add(@"iOSHotspot", @[
            [self row:@"版本" value:IHText(status[@"version"]).length ? IHText(status[@"version"]) : NSBundle.mainBundle.infoDictionary[@"CFBundleShortVersionString"] action:nil],
            [self row:@"iOS" value:IHText(status[@"osVersion"]).length ? IHText(status[@"osVersion"]) : UIDevice.currentDevice.systemVersion action:nil],
            [self row:@"复制诊断报告" value:@"生成并复制到本机剪贴板" action:@"report"]
        ], @"报告由后台服务本地生成。本应用不会自动发送报告；请自行检查后再分享。");
        add(@"本地数据", @[
            [self row:@"清除流量与客户端历史" value:@"删除手机上的统计和设备记录" action:@"clear"]
        ], @"热点总量与客户端元数据最多保留 30 天。不会记录或展示流量内容。");
        add(@"快捷操作", @[
            [self row:@"快捷操作" value:@"使用系统快捷指令" action:@"shortcuts"]
        ], @"本工具不提供额外或免费流量。实际可用性与设备、系统、越狱和运营商有关。");
    } else if (self.page == IHPageShortcuts) {
        add(@"系统快捷指令", @[
            [self row:@"复制开启 URL" value:@"ios-hotspot://start" action:@"copyStart"],
            [self row:@"复制关闭 URL" value:@"ios-hotspot://stop" action:@"copyStop"],
            [self row:@"复制切换 URL" value:@"ios-hotspot://toggle" action:@"copyToggle"]
        ], @"在快捷指令中添加“URL”和“打开 URL”操作，填入以上地址。运行时应用将请求后台服务执行，并显示真实结果。");
        add(@"主屏幕快捷操作", @[[self row:@"长按 iOSHotspot 图标" value:@"可选择开启、关闭或切换热点。" action:nil]], @"安装完成并刷新主屏幕图标后可用。所有入口共用后台服务的权限、来源检查和自动规则。");
        add(@"控制中心", @[[self row:@"可选扩展" value:@"控制中心模块需安装支持当前系统的 CCSupport。" action:nil]], @"是否安装及能否使用以设备上的实际扩展和后台服务状态为准。");
    }
    self.sections = sections; self.headers = headers; self.footers = footers;
    [self.tableView reloadData];
}
- (void)updateQRForSSID:(NSString *)ssid password:(NSString *)password {
    // Wi-Fi 二维码的保留字符必须逐字符转义，避免双重转义。
    NSString *(^escape)(NSString *) = ^NSString *(NSString *text) {
        NSMutableString *result = [NSMutableString new];
        NSCharacterSet *special = [NSCharacterSet characterSetWithCharactersInString:@"\\;,:\""];
        for (NSUInteger index = 0; index < text.length; index++) {
            unichar character = [text characterAtIndex:index];
            if ([special characterIsMember:character]) [result appendString:@"\\"];
            [result appendFormat:@"%C", character];
        }
        return result;
    };
    NSString *payload = [NSString stringWithFormat:@"WIFI:T:WPA;S:%@;P:%@;;", escape(ssid), escape(password)];
    if ([payload isEqual:self.qrPayload] && self.qrImage) return;
    CGImageRef bitmap = IHCreateQRCodeImage(payload);
    self.qrImage = bitmap ? [UIImage imageWithCGImage:bitmap] : nil;
    self.qrPayload = self.qrImage ? payload : nil;
    if (bitmap) CGImageRelease(bitmap);
}
- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return self.sections.count; }
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section { return self.sections[section].count; }
- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section { return self.headers[section]; }
- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section { return self.footers[section]; }
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    NSDictionary *row = self.sections[indexPath.section][indexPath.row];
    if (row[@"qr"]) {
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        cell.backgroundColor = UIColor.whiteColor;
        UIImageView *imageView = [[UIImageView alloc] initWithImage:self.qrImage];
        imageView.contentMode = UIViewContentModeScaleAspectFit;
        imageView.translatesAutoresizingMaskIntoConstraints = NO;
        imageView.layer.magnificationFilter = kCAFilterNearest;
        imageView.isAccessibilityElement = YES;
        imageView.accessibilityLabel = @"扫描此二维码加入手机当前热点";
        [cell.contentView addSubview:imageView];
        [NSLayoutConstraint activateConstraints:@[
            [imageView.topAnchor constraintEqualToAnchor:cell.contentView.topAnchor constant:24],
            [imageView.bottomAnchor constraintEqualToAnchor:cell.contentView.bottomAnchor constant:-24],
            [imageView.centerXAnchor constraintEqualToAnchor:cell.contentView.centerXAnchor],
            [imageView.widthAnchor constraintEqualToAnchor:cell.contentView.widthAnchor multiplier:0.78],
            [imageView.heightAnchor constraintEqualToAnchor:imageView.widthAnchor]
        ]];
        return cell;
    }
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.text = row[@"title"];
    cell.textLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    cell.textLabel.adjustsFontForContentSizeCategory = YES;
    cell.textLabel.numberOfLines = 0;
    cell.detailTextLabel.text = row[@"value"];
    cell.detailTextLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleSubheadline];
    cell.detailTextLabel.adjustsFontForContentSizeCategory = YES;
    cell.detailTextLabel.numberOfLines = 0;
    cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
    cell.selectionStyle = row[@"action"] ? UITableViewCellSelectionStyleDefault : UITableViewCellSelectionStyleNone;
    if (row[@"switch"]) {
        UISwitch *toggle = [UISwitch new];
        toggle.on = [row[@"switch"] boolValue];
        toggle.accessibilityLabel = row[@"title"];
        toggle.accessibilityIdentifier = row[@"action"];
        toggle.enabled = IHStore.shared.connected && !IHStore.shared.commandInFlight && !IHStore.shared.hotspotTarget;
        if ([row[@"disabled"] boolValue]) toggle.enabled = NO;
        if ([row[@"action"] isEqual:@"compatibility"] && IHStore.shared.compatibilityBusy) toggle.enabled = NO;
        [toggle addTarget:self action:@selector(toggleChanged:) forControlEvents:UIControlEventValueChanged];
        cell.accessoryView = toggle;
        if ([row[@"action"] isEqual:@"hotspot"] && IHStore.shared.hotspotTarget) {
            UIActivityIndicatorView *progress = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
            [progress startAnimating]; cell.accessoryView = progress;
            cell.detailTextLabel.text = IHStore.shared.hotspotTarget.boolValue ? @"正在开启…" : @"正在关闭…";
        }
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
    } else if ([row[@"checked"] boolValue]) {
        cell.accessoryType = UITableViewCellAccessoryCheckmark;
    } else if (row[@"action"]) {
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    }
    if ([row[@"action"] isEqual:@"clear"]) cell.textLabel.textColor = UIColor.systemRedColor;
    return cell;
}
- (void)toggleChanged:(UISwitch *)toggle {
    NSString *action = toggle.accessibilityIdentifier;
    if ([action isEqual:@"autoVPN"]) {
        [self setConfigKey:@"autoVPN" value:@(toggle.on)];
        return;
    }
    if ([action isEqual:@"compatibility"]) {
        [IHStore.shared setCompatibility:toggle.on presenter:self];
        return;
    }
    if ([action isEqual:@"vpnIPv6"]) {
        [self setConfigKey:@"vpnIPv6" value:@(toggle.on)];
        return;
    }
    if ([action isEqual:@"enabled"]) {
        if (!toggle.on) {
            // 禁用会回滚项目网络状态，先说明影响，再交由后台服务执行。
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"停用 iOSHotspot？" message:@"后台服务将结束由本项目启动的共享并回滚本项目的网络更改。" preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:^(UIAlertAction *a) { [self rebuild]; }]];
            [alert addAction:[UIAlertAction actionWithTitle:@"停用" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) { [IHStore.shared send:@{@"command": @"disable"} presenter:self completion:nil]; }]];
            [self presentViewController:alert animated:YES completion:nil];
        } else {
            [IHStore.shared send:@{@"command": @"enable"} presenter:self completion:nil];
        }
    } else {
        [self performHotspotAction:toggle.on ? @"start" : @"stop"];
    }
}
- (void)performHotspotAction:(NSString *)action {
    if (![(@[@"start", @"stop", @"toggle"]) containsObject:action]) return;
    [IHStore.shared send:@{@"command": action} presenter:self completion:^(NSDictionary *response) {
        [self rebuild];
    }];
}
- (void)showPage:(IHPage)page {
    [self.navigationController pushViewController:[[IHViewController alloc] initWithPage:page] animated:YES];
}
- (void)showAbout { [self showPage:IHPageAbout]; }
- (void)copyText:(NSString *)text title:(NSString *)title {
    if (!text.length) { IHAlert(self, @"无法复制", @"没有可读取的内容。"); return; }
    // 密码与诊断只写本机剪贴板，避免被系统通用剪贴板自动同步到其他设备。
    [UIPasteboard.generalPasteboard setItems:@[@{UIPasteboardTypeAutomatic:text}] options:@{UIPasteboardOptionLocalOnly:@YES}];
    UIAccessibilityPostNotification(UIAccessibilityAnnouncementNotification, title);
    IHAlert(self, title, @"已复制到本机剪贴板。");
}
- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    NSDictionary *row = self.sections[indexPath.section][indexPath.row];
    NSString *action = row[@"action"];
    if ([action isEqual:@"refresh"]) [IHStore.shared refresh];
    else if ([action isEqual:@"source"]) [self showPage:IHPageSource];
    else if ([action isEqual:@"join"]) [self showPage:IHPageJoin];
    else if ([action isEqual:@"rules"]) [self showPage:IHPageRules];
    else if ([action isEqual:@"history"]) [self showPage:IHPageHistory];
    else if ([action isEqual:@"shortcuts"]) [self showPage:IHPageShortcuts];
    else if ([action isEqual:@"copyPassword"]) {
        [self copyText:IHText(IHStore.shared.status[@"password"]) title:@"密码已复制"];
    } else if ([action isEqual:@"selectSource"]) {
        [IHStore.shared send:@{@"command": @"configure", @"config": @{@"source": row[@"source"]}} presenter:self completion:nil];
    } else if ([action isEqual:@"idle"]) [self selectIdle];
    else if ([action isEqual:@"battery"]) [self selectBattery];
    else if ([action isEqual:@"limit"]) [self selectLimit];
    else if ([action isEqual:@"rename"]) [self renameClient:row[@"client"]];
    else if ([action isEqual:@"report"]) {
        [IHStore.shared send:@{@"command": @"report"} presenter:self completion:^(NSDictionary *response) {
            [self copyText:IHText(response[@"report"]) title:@"诊断报告已复制"];
        }];
    } else if ([action isEqual:@"clear"]) [self confirmClear];
    else if ([action hasPrefix:@"copy"]) {
        NSDictionary *urls = @{@"copyStart": @"ios-hotspot://start", @"copyStop": @"ios-hotspot://stop", @"copyToggle": @"ios-hotspot://toggle"};
        if (urls[action]) [self copyText:urls[action] title:@"快捷指令 URL 已复制"];
    }
}
- (void)setConfigKey:(NSString *)key value:(id)value {
    [IHStore.shared send:@{@"command": @"configure", @"config": @{key: value}} presenter:self completion:nil];
}
- (void)showChoices:(NSString *)title values:(NSArray<NSNumber *> *)values format:(NSString *(^)(NSNumber *))format key:(NSString *)key {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:nil preferredStyle:UIAlertControllerStyleActionSheet];
    for (NSNumber *value in values) {
        [alert addAction:[UIAlertAction actionWithTitle:format(value) style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) { [self setConfigKey:key value:value]; }]];
    }
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    if (alert.popoverPresentationController) {
        alert.popoverPresentationController.sourceView = self.view;
        alert.popoverPresentationController.sourceRect = CGRectMake(CGRectGetMidX(self.view.bounds), CGRectGetMidY(self.view.bounds), 1, 1);
    }
    [self presentViewController:alert animated:YES completion:nil];
}
- (void)selectIdle {
    [self showChoices:@"无客户端时关闭" values:@[@0, @5, @10, @15, @30, @60] format:^NSString *(NSNumber *value) {
        return value.integerValue == 0 ? @"关闭此规则" : [NSString stringWithFormat:@"%@ 分钟", value];
    } key:@"idleMinutes"];
}
- (void)selectBattery {
    [self showChoices:@"低电量关闭" values:@[@0, @5, @10, @15, @20, @25, @30, @40, @50] format:^NSString *(NSNumber *value) {
        return value.integerValue == 0 ? @"关闭此规则" : [NSString stringWithFormat:@"不高于 %@%%", value];
    } key:@"lowBatteryPercent"];
}
- (void)selectLimit {
    NSDictionary *config = IHStore.shared.status[@"config"];
    double mebibytes = [config[@"dailyLimitBytes"] doubleValue] / (1024.0 * 1024.0);
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"每日流量额度" message:@"单位为 MiB（1 MiB = 1,048,576 字节）。输入 0 表示不设额度。" preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.keyboardType = UIKeyboardTypeDecimalPad;
        field.text = [NSString stringWithFormat:@"%.3f", mebibytes];
        field.placeholder = @"例如 1024";
        field.accessibilityLabel = @"每日流量额度 MiB";
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        NSString *text = [alert.textFields.firstObject.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        NSScanner *scanner = [NSScanner scannerWithString:text];
        double number = 0;
        BOOL valid = [scanner scanDouble:&number] && scanner.isAtEnd && isfinite(number) && number >= 0 && number <= 100000000;
        if (!valid) {
            dispatch_async(dispatch_get_main_queue(), ^{ IHAlert(self, @"额度无效", @"请输入不小于 0 且不超过 100,000,000 的 MiB 数值。"); });
            return;
        }
        [self setConfigKey:@"dailyLimitBytes" value:@((unsigned long long)llround(number * 1048576.0))];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}
- (void)renameClient:(NSDictionary *)client {
    NSString *identifier = IHText(client[@"id"]);
    if (!identifier.length) { IHAlert(self, @"无法重命名", @"该记录没有可用的客户端标识。"); return; }
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"重命名客户端" message:@"名称保存在本机，不会修改设备本身。" preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.text = IHText(client[@"name"]);
        field.placeholder = @"设备名称";
        field.clearButtonMode = UITextFieldViewModeWhileEditing;
        field.accessibilityLabel = @"客户端名称";
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        NSString *name = [alert.textFields.firstObject.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        if (!name.length || name.length > 64) {
            dispatch_async(dispatch_get_main_queue(), ^{ IHAlert(self, @"名称无效", @"请输入 1–64 个字符。"); });
            return;
        }
        [IHStore.shared send:@{@"command": @"rename", @"id": identifier, @"name": name} presenter:self completion:nil];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}
- (void)confirmClear {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"清除本地数据？" message:@"将删除热点流量统计、客户端历史与自定义名称。此操作无法撤销。自动关闭规则由后台服务单独保存。" preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"清除" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
        [IHStore.shared send:@{@"command": @"clear"} presenter:self completion:nil];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}
@end

@interface IHAppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@property(nonatomic, strong) IHViewController *dashboard;
@property(nonatomic, strong) UINavigationController *navigation;
@end

@implementation IHAppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.tintColor = UIColor.systemBlueColor;
    self.dashboard = [[IHViewController alloc] initWithPage:IHPageDashboard];
    self.navigation = [[UINavigationController alloc] initWithRootViewController:self.dashboard];
    self.navigation.navigationBar.prefersLargeTitles = YES;
    self.window.rootViewController = self.navigation;
    [self.window makeKeyAndVisible];
    UIApplicationShortcutItem *shortcut = options[UIApplicationLaunchOptionsShortcutItemKey];
    if (shortcut) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self handleAction:shortcut.type.lastPathComponent]; });
        return NO;
    }
    return YES;
}
- (void)applicationDidBecomeActive:(UIApplication *)application { [IHStore.shared activate]; }
- (void)applicationWillResignActive:(UIApplication *)application { [IHStore.shared deactivate]; }
- (void)applicationDidEnterBackground:(UIApplication *)application { [IHStore.shared deactivate]; }
- (void)applicationWillTerminate:(UIApplication *)application { [IHStore.shared deactivate]; }
- (BOOL)handleAction:(NSString *)action {
    if ([action isEqualToString:@"status"]) { [(UINavigationController *)self.window.rootViewController popToRootViewControllerAnimated:NO]; [[IHStore shared] refresh]; return YES; }
    if (![(@[@"start", @"stop", @"toggle"]) containsObject:action]) return NO;
    [self.navigation popToRootViewControllerAnimated:NO];
    [self.dashboard performHotspotAction:action];
    return YES;
}
- (BOOL)application:(UIApplication *)application openURL:(NSURL *)url options:(NSDictionary<UIApplicationOpenURLOptionsKey,id> *)options {
    if (![url.scheme.lowercaseString isEqualToString:@"ios-hotspot"]) return NO;
    return [self handleAction:url.host.lowercaseString];
}
- (void)application:(UIApplication *)application performActionForShortcutItem:(UIApplicationShortcutItem *)shortcutItem completionHandler:(void (^)(BOOL))completionHandler {
    completionHandler([self handleAction:shortcutItem.type.lastPathComponent]);
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(IHAppDelegate.class));
    }
}
