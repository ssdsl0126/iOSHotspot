#import "IHStore.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>

static const NSTimeInterval IHRetention = 30.0 * 24.0 * 60.0 * 60.0;
static const NSTimeInterval IHBucketSeconds = 60.0;
static NSString *const IHErrorDomain = @"com.newbie.ioshotspot.store";

static NSError *IHError(NSInteger code, NSString *text) {
    return [NSError errorWithDomain:IHErrorDomain code:code userInfo:@{NSLocalizedDescriptionKey:text}];
}

static BOOL IHNumber(id value) {
    return [value isKindOfClass:NSNumber.class] && isfinite([value doubleValue]);
}

static BOOL IHInteger(id value, double low, double high) {
    if (!IHNumber(value)) return NO;
    double number = [value doubleValue];
    return number >= low && number <= high && floor(number) == number;
}

static uint64_t IHSaturatedAdd(uint64_t left, uint64_t right) {
    return UINT64_MAX - left < right ? UINT64_MAX : left + right;
}

@interface IHStore ()
@property(nonatomic, readwrite, copy) NSDictionary *config;
@property(nonatomic, readwrite, nullable, strong) NSError *lastError;
@property(nonatomic, readwrite) BOOL readOnly;
@property(nonatomic, copy) NSString *directory;
@property(nonatomic, copy) NSString *path;
@property(nonatomic, strong) NSMutableDictionary<NSString *, NSMutableDictionary *> *buckets;
@property(nonatomic, strong) NSMutableDictionary<NSString *, NSMutableDictionary *> *clients;
@property(nonatomic, strong) NSMutableArray<NSDictionary *> *events;
@property(nonatomic) BOOL dirty;
@property(nonatomic, nullable, strong) NSDate *persistedExpiryDate;
@end

@implementation IHStore

+ (NSDictionary *)defaultConfig {
    return @{ @"enabled":@NO, @"source":@"cellular", @"idleMinutes":@0,
              @"lowBatteryPercent":@0, @"dailyLimitBytes":@0, @"vpnIPv6":@NO, @"autoVPN":@NO };
}

+ (BOOL)validConfig:(NSDictionary *)config {
    if (![config isKindOfClass:NSDictionary.class]) return NO;
    NSSet *keys = [NSSet setWithArray:[self defaultConfig].allKeys];
    for (id key in config) if (![key isKindOfClass:NSString.class] || ![keys containsObject:key]) return NO;
    if (config.count != keys.count || !IHInteger(config[@"enabled"],0,1)) return NO;
    if (!IHInteger(config[@"vpnIPv6"],0,1)) return NO;
    if (!IHInteger(config[@"autoVPN"],0,1)) return NO;
    if (![@[@"cellular",@"wifi",@"vpn",@"auto"] containsObject:config[@"source"]]) return NO;
    if (!IHInteger(config[@"idleMinutes"],0,60) || ![@[@0,@5,@10,@15,@30,@60] containsObject:config[@"idleMinutes"]]) return NO;
    if (!IHInteger(config[@"lowBatteryPercent"],0,100)) return NO;
    // JSON 数字精度之外的额度无实际意义，避免截断后阈值失真。
    return IHInteger(config[@"dailyLimitBytes"],0,9007199254740991.0);
}

- (instancetype)initWithDirectory:(NSString *)directory {
    self = [super init];
    if (!self) return nil;
    _directory = [directory copy];
    _path = [directory stringByAppendingPathComponent:@"store.json"];
    _config = [IHStore defaultConfig];
    _buckets = [NSMutableDictionary dictionary];
    _clients = [NSMutableDictionary dictionary];
    _events = [NSMutableArray array];
    NSError *error = nil;
    struct stat info;
    if (lstat(directory.fileSystemRepresentation,&info) == 0 && (!S_ISDIR(info.st_mode) || S_ISLNK(info.st_mode))) {
        [self fail:IHError(1,@"数据目录不是普通目录，已拒绝写入。")];
        return self;
    }
    if (![NSFileManager.defaultManager createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions:@0700} error:&error] || chmod(directory.fileSystemRepresentation,0700) != 0) {
        [self fail:error ?: IHError(errno,@"无法保护数据目录权限。")];
        return self;
    }
    if (lstat(_path.fileSystemRepresentation,&info) != 0) {
        if (errno != ENOENT) [self fail:IHError(errno,@"无法读取数据文件信息。")];
        else _dirty = YES;
        return self;
    }
    if (!S_ISREG(info.st_mode) || S_ISLNK(info.st_mode) || info.st_size > 24 * 1024 * 1024) {
        [self fail:IHError(2,@"数据文件类型或大小异常，原文件已保留且禁止覆盖。")];
        return self;
    }
    chmod(_path.fileSystemRepresentation,0600);
    NSData *data = [NSData dataWithContentsOfFile:_path options:0 error:&error];
    id root = data ? [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:&error] : nil;
    if (![self loadRoot:root]) {
        [self fail:IHError(3,[NSString stringWithFormat:@"数据文件损坏或版本不兼容，原文件已保留且禁止覆盖。%@",error ? error.localizedDescription : @""])];
        return self;
    }
    // 先记住磁盘原始记录的期限，再在内存淘汰；save失败时仍知道旧文件待清理。
    _persistedExpiryDate = [self earliestExpiryInMemory];
    [self expireAt:NSDate.date];
    return self;
}

- (void)fail:(NSError *)error { self.lastError = error; self.readOnly = YES; }

- (BOOL)loadRoot:(id)root {
    if (![root isKindOfClass:NSDictionary.class] || ![root[@"schema"] isEqual:@1] || ![root[@"config"] isKindOfClass:NSDictionary.class]) return NO;
    // 缺少此选项的旧配置默认关闭IPv6，保留已有明确选择和其他数据。
    NSMutableDictionary *configuration = [root[@"config"] mutableCopy];
    BOOL migrated = configuration[@"vpnIPv6"] == nil || configuration[@"autoVPN"] == nil;
    if (configuration[@"vpnIPv6"] == nil) configuration[@"vpnIPv6"] = @NO;
    if (configuration[@"autoVPN"] == nil) configuration[@"autoVPN"] = @NO;
    if (![IHStore validConfig:configuration]) return NO;
    NSDictionary *buckets = root[@"buckets"], *clients = root[@"clients"];
    NSArray *events = root[@"events"];
    if (![buckets isKindOfClass:NSDictionary.class] || buckets.count > 43202 || ![clients isKindOfClass:NSDictionary.class] || clients.count > 10000 || ![events isKindOfClass:NSArray.class] || events.count > 10000) return NO;
    for (id key in buckets) {
        id bucket = buckets[key];
        if (![key isKindOfClass:NSString.class] || ![bucket isKindOfClass:NSDictionary.class] || !IHNumber(bucket[@"t"]) || !IHNumber(bucket[@"rx"]) || !IHNumber(bucket[@"tx"]) || [bucket[@"rx"] doubleValue] < 0 || [bucket[@"tx"] doubleValue] < 0) return NO;
    }
    for (id key in clients) {
        id client = clients[key];
        if (![key isKindOfClass:NSString.class] || ![client isKindOfClass:NSDictionary.class] || ![key isEqual:client[@"id"]] || ![client[@"name"] isKindOfClass:NSString.class] || ![client[@"transport"] isKindOfClass:NSString.class] || !IHNumber(client[@"firstSeen"]) || !IHNumber(client[@"lastSeen"])) return NO;
    }
    for (id event in events) if (![event isKindOfClass:NSDictionary.class] || !IHNumber(event[@"t"]) || ![event[@"type"] isKindOfClass:NSString.class] || ![event[@"details"] isKindOfClass:NSDictionary.class]) return NO;
    self.config = configuration;
    if (migrated) self.dirty = YES;
    self.buckets = [buckets mutableCopy];
    for (NSString *key in buckets) self.buckets[key] = [buckets[key] mutableCopy];
    self.clients = [clients mutableCopy];
    for (NSString *key in clients) {
        self.clients[key] = [clients[key] mutableCopy];
        // 重启前的连接标志不能冒充当前在线状态，等待系统重新观察。
        self.clients[key][@"connected"] = @NO;
    }
    self.events = [events mutableCopy];
    return YES;
}

- (BOOL)updateConfig:(NSDictionary *)changes error:(NSError **)error {
    @synchronized(self) {
        if (self.readOnly) { if (error) *error = self.lastError; return NO; }
        if (![changes isKindOfClass:NSDictionary.class]) { if (error) *error = IHError(4,@"规则必须是字典。"); return NO; }
        NSMutableDictionary *next = self.config.mutableCopy;
        [next addEntriesFromDictionary:changes];
        if (![IHStore validConfig:next]) {
            if (error) *error = IHError(4,@"无效规则：来源、空闲时长、电量或每日额度超出范围。");
            return NO;
        }
        NSDictionary *previous = self.config;
        self.config = next;
        self.dirty = YES;
        if (![self save]) { self.config = previous; if (error) *error = self.lastError; return NO; }
        return YES;
    }
}

- (void)recordRx:(uint64_t)rx tx:(uint64_t)tx at:(NSDate *)date {
    @synchronized(self) {
        if (self.readOnly || (rx == 0 && tx == 0)) return;
        NSTimeInterval stamp = floor(date.timeIntervalSince1970 / IHBucketSeconds) * IHBucketSeconds;
        if (!isfinite(stamp)) return;
        [self expireAt:date];
        NSString *key = [NSString stringWithFormat:@"%.0f",stamp];
        NSMutableDictionary *bucket = self.buckets[key];
        if (!bucket) { bucket = [@{@"t":@(stamp), @"rx":@0, @"tx":@0} mutableCopy]; self.buckets[key] = bucket; }
        bucket[@"rx"] = @(IHSaturatedAdd([bucket[@"rx"] unsignedLongLongValue],rx));
        bucket[@"tx"] = @(IHSaturatedAdd([bucket[@"tx"] unsignedLongLongValue],tx));
        self.dirty = YES;
    }
}

- (NSDictionary *)totalsAt:(NSDate *)date {
    @synchronized(self) {
        [self expireAt:date];
        NSCalendar *calendar = NSCalendar.currentCalendar;
        NSDate *day = [calendar startOfDayForDate:date];
        NSDate *month = nil;
        [calendar rangeOfUnit:NSCalendarUnitMonth startDate:&month interval:NULL forDate:date];
        NSTimeInterval now = date.timeIntervalSince1970;
        NSTimeInterval cutoffs[] = {day.timeIntervalSince1970,month.timeIntervalSince1970,now-7*86400.0,now-IHRetention};
        uint64_t rx[4] = {0}, tx[4] = {0};
        for (NSDictionary *bucket in self.buckets.allValues) {
            NSTimeInterval stamp = [bucket[@"t"] doubleValue];
            if (stamp > now) continue;
            for (int i=0;i<4;i++) if (stamp >= cutoffs[i]) { rx[i] = IHSaturatedAdd(rx[i],[bucket[@"rx"] unsignedLongLongValue]); tx[i] = IHSaturatedAdd(tx[i],[bucket[@"tx"] unsignedLongLongValue]); }
        }
        return @{ @"todayRx":@(rx[0]), @"todayTx":@(tx[0]), @"monthRx":@(rx[1]), @"monthTx":@(tx[1]),
                  @"sevenDaysRx":@(rx[2]), @"sevenDaysTx":@(tx[2]), @"thirtyDaysRx":@(rx[3]), @"thirtyDaysTx":@(tx[3]),
                  @"retentionSeconds":@(IHRetention), @"bucketSeconds":@(IHBucketSeconds),
                  @"monthCoverage":@"本月且位于最近30天内；分钟桶边界最多提前59秒清理" };
    }
}

- (NSArray<NSDictionary *> *)observeClients:(NSArray<NSDictionary *> *)clients at:(NSDate *)date {
    @synchronized(self) {
        if (!self.readOnly) {
            [self expireAt:date];
            for (NSMutableDictionary *old in self.clients.allValues) old[@"connected"] = @NO;
            for (id raw in clients) {
                if (![raw isKindOfClass:NSDictionary.class]) continue;
                NSString *identity = raw[@"id"];
                if (![identity isKindOfClass:NSString.class] || identity.length == 0 || identity.length > 256) continue;
                NSMutableDictionary *record = self.clients[identity];
                if (!record) {
                    if (self.clients.count >= 10000) continue;
                    NSString *name = [raw[@"name"] isKindOfClass:NSString.class] ? raw[@"name"] : identity;
                    record = [@{ @"id":identity, @"name":[name substringToIndex:MIN(name.length,128)], @"firstSeen":@(date.timeIntervalSince1970) } mutableCopy];
                    self.clients[identity] = record;
                }
                NSString *transport = [raw[@"transport"] isKindOfClass:NSString.class] ? raw[@"transport"] : @"unknown";
                record[@"transport"] = [transport substringToIndex:MIN(transport.length,64)];
                record[@"lastSeen"] = @(date.timeIntervalSince1970);
                record[@"connected"] = @YES;
            }
            self.dirty = YES;
        }
        return [self historyAt:date];
    }
}

- (BOOL)renameClient:(NSString *)identity name:(NSString *)name error:(NSError **)error {
    @synchronized(self) {
        if (self.readOnly) { if (error) *error = self.lastError; return NO; }
        if (![identity isKindOfClass:NSString.class] || !self.clients[identity] || ![name isKindOfClass:NSString.class]) { if (error) *error = IHError(5,@"未找到客户端。"); return NO; }
        NSString *trimmed = [name stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        if (trimmed.length == 0 || trimmed.length > 128 || [trimmed rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location != NSNotFound) { if (error) *error = IHError(6,@"名称须为1至128个字符，且不能含控制字符。"); return NO; }
        NSMutableDictionary *client = self.clients[identity];
        NSString *previous = client[@"name"];
        client[@"name"] = trimmed;
        self.dirty = YES;
        if (![self save]) { client[@"name"] = previous; if (error) *error = self.lastError; return NO; }
        return YES;
    }
}

- (NSArray<NSDictionary *> *)historyAt:(NSDate *)date {
    @synchronized(self) {
        [self expireAt:date];
        NSMutableArray *result = [NSMutableArray array];
        for (NSDictionary *client in self.clients.allValues) [result addObject:[client copy]];
        [result sortUsingComparator:^NSComparisonResult(NSDictionary *left, NSDictionary *right) { return [right[@"lastSeen"] compare:left[@"lastSeen"]]; }];
        return result;
    }
}

- (void)appendEvent:(NSString *)type details:(NSDictionary *)details at:(NSDate *)date {
    @synchronized(self) {
        if (self.readOnly || ![type isKindOfClass:NSString.class] || type.length == 0 || type.length > 128) return;
        // 显式白名单保证事件无法意外写入密码、DNS 请求或流量内容。
        NSSet *allowed = [NSSet setWithArray:@[@"source",@"reason",@"interface",@"state",@"rx",@"tx",@"threshold",@"battery",@"count",@"code"]];
        NSMutableDictionary *safe = [NSMutableDictionary dictionary];
        if ([details isKindOfClass:NSDictionary.class]) for (NSString *key in allowed) {
            id value = details[key];
            if (IHNumber(value) || ([value isKindOfClass:NSString.class] && [value length] <= 256)) safe[key] = value;
        }
        [self expireAt:date];
        [self.events addObject:@{@"t":@(date.timeIntervalSince1970), @"type":type, @"details":safe}];
        if (self.events.count > 10000) [self.events removeObjectsInRange:NSMakeRange(0,self.events.count-10000)];
        self.dirty = YES;
    }
}

- (NSArray<NSDictionary *> *)eventsAt:(NSDate *)date {
    @synchronized(self) { [self expireAt:date]; return [[NSArray alloc] initWithArray:self.events copyItems:YES]; }
}

- (void)expireAt:(NSDate *)date {
    @synchronized(self) {
        if (self.readOnly) return;
        NSTimeInterval now = date.timeIntervalSince1970;
        // 与nextExpiry完全使用同一加法，避免浮点减法抵消使精确deadline漏删。
        for (NSString *key in self.buckets.allKeys) if ([self.buckets[key][@"t"] doubleValue] + IHRetention <= now) { [self.buckets removeObjectForKey:key]; self.dirty = YES; }
        for (NSString *key in self.clients.allKeys) if ([self.clients[key][@"lastSeen"] doubleValue] + IHRetention <= now) { [self.clients removeObjectForKey:key]; self.dirty = YES; }
        NSIndexSet *expired = [self.events indexesOfObjectsPassingTest:^BOOL(NSDictionary *event, NSUInteger idx, BOOL *stop) { return [event[@"t"] doubleValue] + IHRetention <= now; }];
        if (expired.count) { [self.events removeObjectsAtIndexes:expired]; self.dirty = YES; }
    }
}

- (NSDate *)earliestExpiryInMemory {
    NSTimeInterval earliest = INFINITY;
    for (NSDictionary *bucket in self.buckets.allValues) earliest = fmin(earliest,[bucket[@"t"] doubleValue]);
    for (NSDictionary *client in self.clients.allValues) earliest = fmin(earliest,[client[@"lastSeen"] doubleValue]);
    for (NSDictionary *event in self.events) earliest = fmin(earliest,[event[@"t"] doubleValue]);
    return isfinite(earliest) ? [NSDate dateWithTimeIntervalSince1970:earliest + IHRetention] : nil;
}

- (NSDate *)nextExpiryDateAfter:(NSDate *)now {
    @synchronized(self) {
        // 只读损坏状态不能自行删除；保留lastError供调用方报告，避免空转重试。
        if (self.readOnly || !self.persistedExpiryDate) return nil;
        return [self.persistedExpiryDate compare:now] == NSOrderedDescending ? self.persistedExpiryDate : now;
    }
}

- (void)clear {
    @synchronized(self) {
        if (self.readOnly) return;
        [self.buckets removeAllObjects]; [self.clients removeAllObjects]; [self.events removeAllObjects];
        self.dirty = YES;
        [self save];
    }
}

- (BOOL)save {
    @synchronized(self) {
        if (self.readOnly) return NO;
        if (!self.dirty) return YES;
        NSError *error = nil;
        NSDictionary *root = @{ @"schema":@1, @"config":self.config, @"buckets":self.buckets, @"clients":self.clients, @"events":self.events };
        NSData *data = [NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingSortedKeys error:&error];
        if (!data) { self.lastError = error; return NO; }
        NSString *temporary = [self.directory stringByAppendingPathComponent:[NSString stringWithFormat:@".store-%@.tmp",NSUUID.UUID.UUIDString]];
        int fd = open(temporary.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
        if (fd < 0) { self.lastError = IHError(errno,@"无法创建受保护的临时数据文件。"); return NO; }
        const uint8_t *bytes = data.bytes;
        size_t remaining = data.length;
        BOOL okay = YES;
        while (remaining) {
            ssize_t count = write(fd,bytes,remaining);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) { okay = NO; break; }
            bytes += count; remaining -= (size_t)count;
        }
        if (okay && fsync(fd) != 0) okay = NO;
        int savedErrno = errno;
        close(fd);
        if (okay && rename(temporary.fileSystemRepresentation,self.path.fileSystemRepresentation) != 0) { okay = NO; savedErrno = errno; }
        if (!okay) { unlink(temporary.fileSystemRepresentation); self.lastError = IHError(savedErrno,@"数据原子写入失败，原文件已保留。"); return NO; }
        int directoryFd = open(self.directory.fileSystemRepresentation,O_RDONLY|O_DIRECTORY);
        if (directoryFd >= 0) { fsync(directoryFd); close(directoryFd); }
        self.lastError = nil;
        self.dirty = NO;
        self.persistedExpiryDate = [self earliestExpiryInMemory];
        return YES;
    }
}
@end
