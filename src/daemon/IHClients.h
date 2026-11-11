#import <Foundation/Foundation.h>
#include <stdint.h>

NS_ASSUME_NONNULL_BEGIN

// 仅解析以太网及 ARP/IP 固定头中的来源身份；不返回或保存流量内容。
FOUNDATION_EXPORT NSDictionary * _Nullable IHClientMetadataFromEthernetHeader(const uint8_t *bytes, size_t length);

@interface IHClients : NSObject
@property(nonatomic, copy, nullable) void (^changed)(void);
@property(nonatomic, readonly, nullable, copy) NSError *lastError;
@property(nonatomic, readonly, copy) NSDictionary *diagnostics;
- (instancetype)initWithQueue:(dispatch_queue_t)queue;
// 接口须同时位于系统当前内侧接口清单，且只能是 bridge 数字接口或 ap1。
- (void)updateInterfaces:(NSArray<NSString *> *)interfaces systemSnapshot:(NSDictionary *)snapshot;
// connected 为 YES、NO 或 NSNull：静默超过 30 秒只表示未知，不代表断开。
// activeRecent 仅表示近期真实发包；上层展示当前客户端时必须检查此字段。
- (NSArray<NSDictionary *> *)clientsAt:(NSDate *)now;
// 清除观察缓存并保留BPF监听；清除前已排队的包也不能恢复旧历史。
- (void)clearHistory;
- (void)stop;
@end

NS_ASSUME_NONNULL_END
