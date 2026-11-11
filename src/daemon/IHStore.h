#import <Foundation/Foundation.h>
#include <stdint.h>

NS_ASSUME_NONNULL_BEGIN

// 仅保存计量总数与设备元数据；调用方在串行队列上使用，方法本身也做互斥保护。
@interface IHStore : NSObject
@property(nonatomic, readonly, copy) NSDictionary *config;
@property(nonatomic, readonly, nullable, strong) NSError *lastError;
@property(nonatomic, readonly) BOOL readOnly;
- (instancetype)initWithDirectory:(NSString *)directory;
- (BOOL)updateConfig:(NSDictionary *)changes error:(NSError * _Nullable * _Nullable)error;
- (void)recordRx:(uint64_t)rx tx:(uint64_t)tx at:(NSDate *)date;
- (NSDictionary *)totalsAt:(NSDate *)date;
- (NSArray<NSDictionary *> *)observeClients:(NSArray<NSDictionary *> *)clients at:(NSDate *)date;
- (BOOL)renameClient:(NSString *)identity name:(NSString *)name error:(NSError * _Nullable * _Nullable)error;
- (NSArray<NSDictionary *> *)historyAt:(NSDate *)date;
- (void)appendEvent:(NSString *)type details:(NSDictionary *)details at:(NSDate *)date;
- (NSArray<NSDictionary *> *)eventsAt:(NSDate *)date;
- (void)expireAt:(NSDate *)date;
// 返回最近一次成功落盘数据的最早删除期限；已到期返回now，无数据返回nil。
// 内存expire后必须save成功才更新此期限，便于调度失败时立即重试并报告错误。
- (nullable NSDate *)nextExpiryDateAfter:(NSDate *)now;
- (void)clear;
- (BOOL)save;
@end

NS_ASSUME_NONNULL_END
