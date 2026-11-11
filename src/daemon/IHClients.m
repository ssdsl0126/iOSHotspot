#import "IHClients.h"
#include <net/if.h>
#include <net/if_dl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#if __has_include(<net/bpf.h>)
#include <net/bpf.h>
#else
// 部分 patched iOS SDK 未包含 bpf.h。以下仅为 Apple Darwin 公开 BPF ABI 的最小声明。
// 对照 Apple SDK 的 net/bpf.h；LP64 的 BPF 时间戳仍是两个 int32_t，按 4 字节对齐。
// 来源：https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/bpf.h
struct bpf_insn { uint16_t code; uint8_t jt; uint8_t jf; uint32_t k; };
struct bpf_program { unsigned int bf_len; struct bpf_insn *bf_insns; };
struct bpf_hdr { struct { int32_t tv_sec; int32_t tv_usec; } bh_tstamp; uint32_t bh_caplen; uint32_t bh_datalen; uint16_t bh_hdrlen; };
#define BPF_WORDALIGN(value) (((value) + 3U) & ~3U)
#define BIOCGBLEN _IOR('B', 102, unsigned int)
#define BIOCSBLEN _IOWR('B', 102, unsigned int)
#define BIOCSETF _IOW('B', 103, struct bpf_program)
#define BIOCFLUSH _IO('B', 104)
#define BIOCGDLT _IOR('B', 106, unsigned int)
#define BIOCSETIF _IOW('B', 108, struct ifreq)
#define BIOCIMMEDIATE _IOW('B', 112, unsigned int)
#define BIOCSSEESENT _IOW('B', 119, unsigned int)
#define DLT_EN10MB 1
#define BPF_LD 0x00
#define BPF_B 0x10
#define BPF_H 0x08
#define BPF_ABS 0x20
#define BPF_JMP 0x05
#define BPF_JEQ 0x10
#define BPF_JSET 0x40
#define BPF_K 0x00
#define BPF_RET 0x06
#define BPF_STMT(codeValue, value) { (uint16_t)(codeValue), 0, 0, (uint32_t)(value) }
#define BPF_JUMP(codeValue, value, yes, no) { (uint16_t)(codeValue), (yes), (no), (uint32_t)(value) }
#endif

_Static_assert(offsetof(struct bpf_hdr, bh_caplen) == 8, "Darwin BPF timestamp ABI changed");
_Static_assert(offsetof(struct bpf_hdr, bh_hdrlen) == 16, "Darwin BPF header ABI changed");
_Static_assert(sizeof(struct bpf_insn) == 8, "Darwin BPF instruction ABI changed");
static const size_t IHMaximumHeader = 96;
static const NSTimeInterval IHRecentInterval = 30;
static const NSTimeInterval IHRetentionInterval = 30 * 24 * 60 * 60;

static uint16_t IHBE16(const uint8_t *bytes) { return ((uint16_t)bytes[0] << 8) | bytes[1]; }
static NSString *IHMAC(const uint8_t *bytes) {
    return [NSString stringWithFormat:@"%02x:%02x:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]];
}
static BOOL IHUnicastMAC(const uint8_t *bytes) {
    if (bytes[0] & 1) return NO;
    uint8_t any = 0;
    for (NSUInteger index = 0; index < 6; index++) any |= bytes[index];
    return any != 0;
}
static NSString *IHIPv4Text(const uint8_t *bytes) {
    if (!bytes[0] || bytes[0] >= 224 || (bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255)) return nil;
    char text[INET_ADDRSTRLEN];
    return inet_ntop(AF_INET, bytes, text, sizeof(text)) ? @(text) : nil;
}
static NSString *IHIPv6Text(const uint8_t *bytes) {
    BOOL any = NO;
    for (NSUInteger index = 0; index < 16; index++) any |= bytes[index] != 0;
    if (!any || bytes[0] == 0xff) return nil;
    char text[INET6_ADDRSTRLEN];
    return inet_ntop(AF_INET6, bytes, text, sizeof(text)) ? @(text) : nil;
}

NSDictionary *IHClientMetadataFromEthernetHeader(const uint8_t *bytes, size_t length) {
    if (!bytes || length < 14 || length > IHMaximumHeader || !IHUnicastMAC(bytes + 6)) return nil;
    uint16_t type = IHBE16(bytes + 12);
    NSMutableDictionary *metadata = [NSMutableDictionary new];
    NSString *ip = nil;
    if (type == 0x0806) {
        // 仅接受 Ethernet/IPv4 ARP；发送方硬件地址须与以太网来源一致。
        if (length < 42 || IHBE16(bytes + 14) != 1 || IHBE16(bytes + 16) != 0x0800 || bytes[18] != 6 || bytes[19] != 4 || memcmp(bytes + 22, bytes + 6, 6)) return nil;
        uint16_t operation = IHBE16(bytes + 20);
        if (operation != 1 && operation != 2) return nil;
        ip = IHIPv4Text(bytes + 28);
        metadata[@"networkProtocol"] = @"ARP";
    } else if (type == 0x0800) {
        if (length < 34 || (bytes[14] >> 4) != 4 || (bytes[14] & 0x0f) < 5 || IHBE16(bytes + 16) < (bytes[14] & 0x0f) * 4) return nil;
        ip = IHIPv4Text(bytes + 26);
        metadata[@"networkProtocol"] = @"IPv4";
    } else if (type == 0x86dd) {
        if (length < 54 || (bytes[14] >> 4) != 6) return nil;
        ip = IHIPv6Text(bytes + 22);
        metadata[@"networkProtocol"] = @"IPv6";
    } else {
        // VLAN、应用负载和其他协议不进入解析范围。
        return nil;
    }
    metadata[@"id"] = IHMAC(bytes + 6);
    metadata[@"mac"] = metadata[@"id"];
    if (ip) metadata[@"ip"] = ip;
    return metadata;
}

static NSString *IHNormalizedMAC(NSString *value) {
    if (![value isKindOfClass:NSString.class]) return nil;
    NSString *text = [[value componentsSeparatedByString:@","] lastObject];
    NSArray *parts = [text.lowercaseString componentsSeparatedByString:@":"];
    if (parts.count != 6) return nil;
    uint8_t bytes[6];
    NSCharacterSet *hex = [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"];
    for (NSUInteger index = 0; index < 6; index++) {
        NSString *part = parts[index];
        if (!part.length || part.length > 2 || [part rangeOfCharacterFromSet:hex.invertedSet].location != NSNotFound) return nil;
        bytes[index] = (uint8_t)strtoul(part.UTF8String, NULL, 16);
    }
    return IHUnicastMAC(bytes) ? IHMAC(bytes) : nil;
}
static NSSet<NSString *> *IHOwnMACs(void) {
    NSMutableSet *addresses = [NSMutableSet new];
    struct ifaddrs *head = NULL;
    if (getifaddrs(&head) != 0) return nil;
    for (struct ifaddrs *item = head; item; item = item->ifa_next) {
        if (!item->ifa_addr || item->ifa_addr->sa_family != AF_LINK) continue;
        const struct sockaddr_dl *link = (const struct sockaddr_dl *)item->ifa_addr;
        if (link->sdl_alen != 6) continue;
        [addresses addObject:IHMAC((const uint8_t *)LLADDR(link))];
    }
    freeifaddrs(head);
    return addresses;
}
static BOOL IHAllowedInterface(NSString *name) {
    if (![name isKindOfClass:NSString.class] || !name.length || [name lengthOfBytesUsingEncoding:NSUTF8StringEncoding] >= IFNAMSIZ) return NO;
    if ([name isEqualToString:@"ap1"]) return YES;
    if (![name hasPrefix:@"bridge"] || name.length == 6) return NO;
    NSString *suffix = [name substringFromIndex:6];
    NSCharacterSet *digits = [NSCharacterSet characterSetWithCharactersInString:@"0123456789"];
    return [suffix rangeOfCharacterFromSet:digits.invertedSet].location == NSNotFound;
}
static NSSet<NSString *> *IHSystemInterfaceNames(id raw) {
    if (![raw isKindOfClass:NSArray.class]) return [NSSet new];
    NSMutableSet *names = [NSMutableSet new];
    for (id entry in raw) {
        if ([entry isKindOfClass:NSString.class]) [names addObject:entry];
        else if ([entry isKindOfClass:NSDictionary.class]) {
            for (NSString *key in @[@"InterfaceName", @"interfaceName", @"Name", @"Interface", @"interface"]) {
                if ([entry[key] isKindOfClass:NSString.class]) { [names addObject:entry[key]]; break; }
            }
        }
    }
    return names;
}

@interface IHClients ()
@property(nonatomic, strong) dispatch_queue_t queue;
@property(nonatomic, strong) NSMutableDictionary<NSString *, dispatch_source_t> *sources;
@property(nonatomic, strong) NSMutableDictionary<NSString *, NSMutableDictionary *> *records;
@property(nonatomic, strong) NSDictionary *systemSnapshot;
@property(nonatomic, strong) NSSet<NSString *> *ownMACs;
@property(nonatomic, strong) NSDictionary<NSString *, NSString *> *leaseNames;
@property(nonatomic, strong) NSDate *leaseModificationDate;
@property(nonatomic, copy, readwrite, nullable) NSError *lastError;
@property(nonatomic, strong) NSDictionary *interfaceErrors;
@property(nonatomic, strong) NSDate *lastAnnouncement;
@property(nonatomic, strong) NSDate *historyClearedAt;
@property(nonatomic) BOOL hotspotOn;
@property(nonatomic) NSUInteger systemCount;
@property(nonatomic) NSUInteger maximumHeaderObserved;
@end

@implementation IHClients
- (instancetype)initWithQueue:(dispatch_queue_t)queue {
    self = [super init];
    if (self) {
        _queue = queue;
        _sources = [NSMutableDictionary new];
        _records = [NSMutableDictionary new];
        _systemSnapshot = @{};
        _ownMACs = [NSSet new];
        _leaseNames = @{};
        _interfaceErrors = @{};
        dispatch_queue_set_specific(queue, (__bridge const void *)self, (__bridge void *)self, NULL);
    }
    return self;
}
- (void)dealloc {
    for (dispatch_source_t source in _sources.allValues) dispatch_source_cancel(source);
    dispatch_queue_set_specific(_queue, (__bridge const void *)self, NULL, NULL);
}
- (void)onQueue:(dispatch_block_t)block {
    if (dispatch_get_specific((__bridge const void *)self)) block();
    else dispatch_sync(self.queue, block);
}
- (NSError *)failure:(NSString *)message code:(NSInteger)code {
    return [NSError errorWithDomain:@"com.newbie.ioshotspot.clients" code:code userInfo:@{NSLocalizedDescriptionKey:message}];
}
- (void)announceIfNeeded:(BOOL)urgent at:(NSDate *)date {
    if (!urgent && self.lastAnnouncement && [date timeIntervalSinceDate:self.lastAnnouncement] < 1) return;
    self.lastAnnouncement = date;
    if (self.changed) self.changed();
}
- (void)stop {
    [self onQueue:^{
        BOOL changed = self.sources.count || self.hotspotOn || self.systemCount;
        for (dispatch_source_t source in self.sources.allValues) dispatch_source_cancel(source);
        [self.sources removeAllObjects];
        self.hotspotOn = NO;
        self.systemCount = 0;
        self.systemSnapshot = @{};
        if (changed) [self announceIfNeeded:YES at:NSDate.date];
    }];
}
- (void)clearHistory {
    [self onQueue:^{
        self.historyClearedAt = NSDate.date;
        [self.records removeAllObjects];
        self.leaseNames = @{};
        self.leaseModificationDate = nil;
        [self announceIfNeeded:YES at:self.historyClearedAt];
    }];
}
- (void)updateInterfaces:(NSArray<NSString *> *)interfaces systemSnapshot:(NSDictionary *)rawSnapshot {
    [self onQueue:^{
        NSDictionary *oldSnapshot = self.systemSnapshot;
        self.systemSnapshot = [rawSnapshot isKindOfClass:NSDictionary.class] ? [rawSnapshot copy] : @{};
        NSDictionary *snapshot = self.systemSnapshot;
        self.hotspotOn = [snapshot[@"hotspotOn"] boolValue];
        self.systemCount = [snapshot[@"clientCount"] unsignedIntegerValue];
        if (!self.hotspotOn) {
            for (dispatch_source_t source in self.sources.allValues) dispatch_source_cancel(source);
            [self.sources removeAllObjects];
            self.interfaceErrors = @{};
            self.lastError = nil;
            if ([oldSnapshot[@"hotspotOn"] boolValue]) [self announceIfNeeded:YES at:NSDate.date];
            return;
        }
        NSSet *ownMACs = IHOwnMACs();
        if (!ownMACs.count) {
            for (dispatch_source_t source in self.sources.allValues) dispatch_source_cancel(source);
            [self.sources removeAllObjects];
            self.lastError = [self failure:@"无法读取手机自身链路地址，不能安全排除本机流量，已关闭元数据监听。" code:EIO];
            self.interfaceErrors = @{@"local-interfaces": self.lastError.localizedDescription};
            return;
        }
        self.ownMACs = ownMACs;
        id internal = snapshot[@"internalInterfaces"];
        NSDictionary *sharing = [snapshot[@"sharing"] isKindOfClass:NSDictionary.class] ? snapshot[@"sharing"] : @{};
        if (![internal isKindOfClass:NSArray.class]) internal = sharing[@"InternalInterfaces"];
        NSSet *reported = IHSystemInterfaceNames(internal);
        id external = snapshot[@"externalInterfaces"];
        if (![external isKindOfClass:NSArray.class]) external = sharing[@"ExternalInterfaces"];
        NSSet *upstreams = IHSystemInterfaceNames(external);
        NSMutableSet *desired = [NSMutableSet new];
        NSMutableDictionary *errors = [NSMutableDictionary new];
        for (id name in interfaces) {
            if (![name isKindOfClass:NSString.class]) continue;
            if (!IHAllowedInterface(name) || ![reported containsObject:name] || [upstreams containsObject:name] || [name isEqual:snapshot[@"primaryInterface"]]) {
                errors[name] = @"拒绝监听：不是系统当前明确报告的热点 bridge/ap1 内侧接口。";
                continue;
            }
            [desired addObject:name];
        }
        for (NSString *name in self.sources.allKeys) {
            if (![desired containsObject:name]) {
                dispatch_source_cancel(self.sources[name]);
                [self.sources removeObjectForKey:name];
            }
        }
        for (NSString *name in desired) {
            if (self.sources[name]) continue;
            NSError *error = nil;
            dispatch_source_t source = [self openInterface:name error:&error];
            if (source) self.sources[name] = source;
            else errors[name] = error.localizedDescription ?: @"BPF 元数据监听不可用。";
        }
        self.interfaceErrors = errors;
        self.lastError = errors.count ? [self failure:[[errors allValues] componentsJoinedByString:@"；"] code:ENOTSUP] : nil;
        if (![oldSnapshot[@"clientCount"] isEqual:snapshot[@"clientCount"]] || ![oldSnapshot[@"transportCounts"] isEqual:snapshot[@"transportCounts"]]) [self announceIfNeeded:YES at:NSDate.date];
    }];
}
- (dispatch_source_t)openInterface:(NSString *)name error:(NSError **)error {
    int fd = -1;
    int savedError = ENOENT;
    for (unsigned int number = 0; number < 256; number++) {
        char path[32];
        snprintf(path, sizeof(path), "/dev/bpf%u", number);
        fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd >= 0) break;
        savedError = errno;
        if (savedError != EBUSY && savedError != ENOENT) break;
        if (savedError == ENOENT && number > 0) break;
    }
    if (fd < 0) {
        if (error) *error = [self failure:[NSString stringWithFormat:@"无法打开 %@ 的只读 BPF：%s", name, strerror(savedError)] code:savedError];
        return nil;
    }
    unsigned int length = 32768;
    const char *operation = "BIOCSBLEN";
    if (ioctl(fd, BIOCSBLEN, &length) < 0) goto failed;
    // 过滤器只返回固定网络头：ARP 42、IPv4 34、IPv6 54 字节。
    // 不使用统一 snaplen，以免短网络头之后的应用负载进入用户空间。
    struct bpf_insn instructions[] = {
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 6),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 1, 8, 0),
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0806, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, 42),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0800, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, 34),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x86dd, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, 54),
        BPF_STMT(BPF_RET | BPF_K, 0),
        BPF_STMT(BPF_RET | BPF_K, 0)
    };
    struct bpf_program program = { sizeof(instructions) / sizeof(instructions[0]), instructions };
    operation = "BIOCSETF";
    if (ioctl(fd, BIOCSETF, &program) < 0) goto failed;
    struct ifreq request;
    memset(&request, 0, sizeof(request));
    strlcpy(request.ifr_name, name.UTF8String, sizeof(request.ifr_name));
    operation = "BIOCSETIF";
    if (ioctl(fd, BIOCSETIF, &request) < 0) goto failed;
    unsigned int linkType = 0;
    operation = "BIOCGDLT";
    if (ioctl(fd, BIOCGDLT, &linkType) < 0) goto failed;
    if (linkType != DLT_EN10MB) {
        if (error) *error = [self failure:[NSString stringWithFormat:@"%@ 的 BPF 链路类型为 %u，不能按以太网元数据安全解析。", name, linkType] code:ENOTSUP];
        close(fd);
        return nil;
    }
    unsigned int immediate = 1, seeSent = 0;
    operation = "BIOCIMMEDIATE";
    if (ioctl(fd, BIOCIMMEDIATE, &immediate) < 0) goto failed;
    operation = "BIOCSSEESENT";
    if (ioctl(fd, BIOCSSEESENT, &seeSent) < 0) goto failed;
    operation = "BIOCFLUSH";
    if (ioctl(fd, BIOCFLUSH, NULL) < 0) goto failed;
    operation = "BIOCGBLEN";
    if (ioctl(fd, BIOCGBLEN, &length) < 0) goto failed;
    if (length < sizeof(struct bpf_hdr) + 54 || length > 524288) {
        if (error) *error = [self failure:@"BPF 返回了不可接受的缓冲区大小，已关闭监听。" code:EOVERFLOW];
        close(fd);
        return nil;
    }
    {
    uint8_t *buffer = calloc(1, length);
    if (!buffer) { savedError = ENOMEM; operation = "BPF buffer"; goto failedWithSavedError; }
    dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)fd, 0, self.queue);
    if (!source) {
        free(buffer);
        savedError = ENOMEM; operation = "BPF dispatch source"; goto failedWithSavedError;
    }
    __weak IHClients *weakSelf = self;
    dispatch_source_set_event_handler(source, ^{
        IHClients *clients = weakSelf;
        if (!clients) return;
        [clients readFD:fd interface:name buffer:buffer length:length];
    });
    dispatch_source_set_cancel_handler(source, ^{
        close(fd);
        // 缓冲区仅在内存短暂存在，关闭时显式清零并释放。
        memset(buffer, 0, length);
        free(buffer);
    });
    dispatch_resume(source);
    return source;
    }
failed:
    savedError = errno;
failedWithSavedError:
    if (error) *error = [self failure:[NSString stringWithFormat:@"%@ 的 %s 不可用：%s", name, operation, strerror(savedError)] code:savedError];
    close(fd);
    return nil;
}
- (void)readFD:(int)fd interface:(NSString *)name buffer:(uint8_t *)buffer length:(size_t)length {
    // 单次事件有限批次读取，避免高吞吐时长时间占用服务串行队列。
    for (NSUInteger batch = 0; batch < 8; batch++) {
        ssize_t count = read(fd, buffer, length);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (count <= 0) {
            int code = count < 0 ? errno : EIO;
            NSString *message = [NSString stringWithFormat:@"%@ 的 BPF 读取已停止：%s", name, strerror(code)];
            self.lastError = [self failure:message code:code];
            NSMutableDictionary *errors = [self.interfaceErrors mutableCopy]; errors[name] = message; self.interfaceErrors = errors;
            if (self.sources[name]) { dispatch_source_cancel(self.sources[name]); [self.sources removeObjectForKey:name]; }
            [self announceIfNeeded:YES at:NSDate.date];
            return;
        }
        size_t offset = 0;
        NSDate *now = NSDate.date;
        BOOL updated = NO, urgent = NO;
        while (offset <= (size_t)count && (size_t)count - offset >= offsetof(struct bpf_hdr, bh_hdrlen) + sizeof(uint16_t)) {
            struct bpf_hdr header;
            memset(&header, 0, sizeof(header));
            memcpy(&header, buffer + offset, MIN(sizeof(header), (size_t)count - offset));
            size_t available = (size_t)count - offset;
            if (header.bh_hdrlen < offsetof(struct bpf_hdr, bh_hdrlen) + sizeof(uint16_t) || header.bh_hdrlen > available || header.bh_caplen > available - header.bh_hdrlen || header.bh_caplen > IHMaximumHeader) break;
            self.maximumHeaderObserved = MAX(self.maximumHeaderObserved, header.bh_caplen);
            const uint8_t *packet = buffer + offset + header.bh_hdrlen;
            NSTimeInterval captured = (NSTimeInterval)header.bh_tstamp.tv_sec + header.bh_tstamp.tv_usec / 1000000.0;
            BOOL afterClear = !self.historyClearedAt || captured > self.historyClearedAt.timeIntervalSince1970;
            NSDictionary *metadata = afterClear ? IHClientMetadataFromEthernetHeader(packet, header.bh_caplen) : nil;
            NSString *identity = metadata[@"id"];
            if (metadata && ![self.ownMACs containsObject:identity] && self.hotspotOn) {
                NSMutableDictionary *record = self.records[identity];
                if (!record && self.records.count < 4096) {
                    record = [NSMutableDictionary new];
                    record[@"id"] = identity; record[@"firstSeen"] = @(captured);
                    self.records[identity] = record; urgent = YES;
                }
                if (record) {
                    NSNumber *previous = record[@"lastPacket"];
                    if (!previous || captured - previous.doubleValue > IHRecentInterval) urgent = YES;
                    record[@"lastSeen"] = @(captured);
                    record[@"lastPacket"] = record[@"lastSeen"];
                    record[@"mac"] = identity; record[@"interface"] = name;
                    record[@"identitySource"] = @"packet-metadata";
                    if (metadata[@"ip"]) record[@"ip"] = metadata[@"ip"];
                    updated = YES;
                }
            }
            size_t block = header.bh_hdrlen + header.bh_caplen;
            size_t aligned = BPF_WORDALIGN(block);
            if (!aligned || aligned > available) break;
            offset += aligned;
        }
        // 从不保留原始报文、端口、目标地址、DNS 内容或应用负载。
        memset(buffer, 0, (size_t)count);
        if (updated) [self announceIfNeeded:urgent at:now];
    }
}
- (void)reloadLeaseNames {
    NSString *path = @"/var/db/dhcpd_leases";
    NSDictionary *attributes = [NSFileManager.defaultManager attributesOfItemAtPath:path error:NULL];
    if (!attributes || [attributes[NSFileSize] unsignedLongLongValue] > 1048576) { self.leaseNames = @{}; self.leaseModificationDate = nil; return; }
    NSDate *modified = attributes[NSFileModificationDate];
    if ([modified isEqualToDate:self.leaseModificationDate]) return;
    self.leaseModificationDate = modified;
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingUncached error:NULL];
    if (data.length > 1048576) return;
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    NSMutableDictionary *names = [NSMutableDictionary new];
    NSMutableDictionary *entry = nil;
    for (NSString *raw in [text componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
        NSString *line = [raw stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        if ([line isEqual:@"{"]) { entry = [NSMutableDictionary new]; continue; }
        if ([line isEqual:@"}"]) {
            NSString *identity = IHNormalizedMAC(entry[@"hw_address"]);
            NSString *name = entry[@"name"];
            if (identity && name.length && name.length <= 128 && [name rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location == NSNotFound) names[identity] = name;
            entry = nil; continue;
        }
        if (!entry) continue;
        NSRange equal = [line rangeOfString:@"="];
        if (equal.location == NSNotFound) continue;
        NSString *key = [[line substringToIndex:equal.location] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if (![key isEqual:@"name"] && ![key isEqual:@"hw_address"]) continue;
        NSString *value = [[line substringFromIndex:equal.location + 1] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if ([value hasPrefix:@"\""] && [value hasSuffix:@"\""] && value.length >= 2) value = [value substringWithRange:NSMakeRange(1, value.length - 2)];
        entry[key] = value;
    }
    self.leaseNames = names;
}
- (NSDictionary *)transportForInterface:(NSString *)name {
    if ([name isEqual:@"ap1"]) return @{@"transport": @"Wi-Fi", @"transportSource": @"interface", @"transportInferred": @NO};
    NSDictionary *counts = [self.systemSnapshot[@"transportCounts"] isKindOfClass:NSDictionary.class] ? self.systemSnapshot[@"transportCounts"] : @{};
    NSString *only = nil;
    NSUInteger nonzero = 0;
    for (NSString *key in counts) {
        if ([counts[key] respondsToSelector:@selector(unsignedIntegerValue)] && [counts[key] unsignedIntegerValue] > 0) { nonzero++; only = key; }
    }
    NSDictionary *mapping = @{@"AirPort": @"Wi-Fi", @"Bluetooth": @"Bluetooth", @"USB-Ethernet": @"USB", @"Ethernet": @"Ethernet"};
    if (self.systemCount > 0 && nonzero == 1 && mapping[only]) return @{@"transport": mapping[only], @"transportSource": @"system-single-transport-inference", @"transportInferred": @YES};
    return @{@"transport": @"unknown", @"transportSource": @"unknown", @"transportInferred": @NO};
}
- (NSArray<NSDictionary *> *)clientsAt:(NSDate *)now {
    __block NSArray *result;
    [self onQueue:^{
        [self reloadLeaseNames];
        NSMutableArray *clients = [NSMutableArray new];
        for (NSString *identity in self.records.allKeys) {
            NSMutableDictionary *record = self.records[identity];
            NSTimeInterval last = [record[@"lastPacket"] doubleValue];
            if (now.timeIntervalSince1970 - last >= IHRetentionInterval) { [self.records removeObjectForKey:identity]; continue; }
            NSMutableDictionary *client = [record mutableCopy];
            BOOL recent = self.hotspotOn && self.systemCount > 0 && now.timeIntervalSince1970 - last <= IHRecentInterval;
            client[@"activeRecent"] = @(recent);
            client[@"connected"] = (!self.hotspotOn || self.systemCount == 0) ? @NO : (recent ? @YES : NSNull.null);
            client[@"connectionState"] = !self.hotspotOn || self.systemCount == 0 ? @"disconnected" : (recent ? @"recent-packet" : @"unknown-idle");
            NSString *leaseName = self.leaseNames[identity];
            client[@"name"] = leaseName ?: identity;
            client[@"nameSource"] = leaseName ? @"dhcp-lease-mac-match" : @"unknown";
            [client addEntriesFromDictionary:[self transportForInterface:record[@"interface"]]];
            [clients addObject:client];
        }
        [clients sortUsingComparator:^NSComparisonResult(NSDictionary *left, NSDictionary *right) { return [right[@"lastPacket"] compare:left[@"lastPacket"]]; }];
        result = clients;
    }];
    return result ?: @[];
}
- (NSDictionary *)diagnostics {
    __block NSDictionary *result;
    [self onQueue:^{
        NSUInteger recent = 0;
        NSDate *now = NSDate.date;
        for (NSDictionary *record in self.records.allValues) if (self.hotspotOn && self.systemCount > 0 && now.timeIntervalSince1970 - [record[@"lastPacket"] doubleValue] <= IHRecentInterval) recent++;
        result = @{
            @"method": @"read-only-bpf-header-metadata", @"activeInterfaces": [self.sources.allKeys sortedArrayUsingSelector:@selector(compare:)],
            @"interfaceErrors": self.interfaceErrors ?: @{}, @"systemClientCount": @(self.systemCount), @"recentIdentityCount": @(recent),
            @"unidentifiedCount": @(self.systemCount > recent ? self.systemCount - recent : 0), @"maximumCapturedHeaderBytes": @(self.maximumHeaderObserved),
            @"kernelCaptureLengths": @[@34, @42, @54], @"rawPacketsPersisted": @NO,
            @"coverage": @"系统总数为准；近期发包才确认身份，静默不等于断开；DHCP 租约只补名称。"
        };
    }];
    return result;
}
@end

#ifdef IHCLIENTS_PARSER_TEST
// 仅验证头部解析边界的合成单测；不代表设备发现、BPF 可用性或真实联网验收。
int main(void) { @autoreleasepool {
    uint8_t packet[96] = {0};
    const uint8_t source[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(packet + 6, source, 6); packet[12] = 0x08; packet[13] = 0x00;
    packet[14] = 0x45; packet[16] = 0; packet[17] = 20;
    packet[26] = 172; packet[27] = 20; packet[28] = 10; packet[29] = 2;
    NSDictionary *ipv4 = IHClientMetadataFromEthernetHeader(packet, 34);
    NSCAssert([ipv4[@"id"] isEqual:@"02:11:22:33:44:55"] && [ipv4[@"ip"] isEqual:@"172.20.10.2"], @"IPv4 来源解析失败");
    NSCAssert(!IHClientMetadataFromEthernetHeader(packet, 33), @"不得接受截断 IPv4");
    packet[6] = 1; NSCAssert(!IHClientMetadataFromEthernetHeader(packet, 34), @"不得接受组播来源"); packet[6] = 2;
    packet[12] = 0x81; packet[13] = 0; NSCAssert(!IHClientMetadataFromEthernetHeader(packet, 34), @"不得推测 VLAN 负载");
    packet[12] = 0x08; packet[13] = 0x06; memset(packet + 14, 0, 82);
    packet[15] = 1; packet[16] = 8; packet[18] = 6; packet[19] = 4; packet[21] = 1;
    memcpy(packet + 22, source, 6); packet[28] = 172; packet[29] = 20; packet[30] = 10; packet[31] = 3;
    NSDictionary *arp = IHClientMetadataFromEthernetHeader(packet, 42);
    NSCAssert([arp[@"ip"] isEqual:@"172.20.10.3"], @"ARP 来源解析失败");
    packet[22] = 4; NSCAssert(!IHClientMetadataFromEthernetHeader(packet, 42), @"不得接受来源 MAC 不一致的 ARP");
    packet[12] = 0x86; packet[13] = 0xdd; memset(packet + 14, 0, 82); packet[14] = 0x60;
    packet[22] = 0xfe; packet[23] = 0x80; packet[37] = 1;
    NSCAssert(IHClientMetadataFromEthernetHeader(packet, 54)[@"ip"] != nil, @"IPv6 来源解析失败");
    NSCAssert(!IHClientMetadataFromEthernetHeader(packet, 97), @"不得接受超过元数据上限的缓冲区");
    puts("PASS: synthetic Ethernet/ARP/IP header parser boundaries; not device acceptance");
    return 0;
} }
#endif
