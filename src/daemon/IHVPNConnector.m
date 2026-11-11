#import "IHVPNConnector.h"
#import "../common/IHPaths.h"
#import "../common/IHTimeouts.h"
#include <spawn.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

@implementation IHVPNConnector {
    BOOL _busy;
    NSUInteger _serial;
    pid_t _pid;
    NSString *_phase, *_error;
}
- (NSString *)helperPath { return IHJailbreakPath(@"/usr/libexec/ioshotspot-vpn-connect"); }
- (BOOL)supported {
    return access(self.helperPath.fileSystemRepresentation, X_OK) == 0;
}
- (BOOL)busy { @synchronized(self) { return _busy; } }
- (NSDictionary *)state { @synchronized(self) { return @{@"supported":@(self.supported), @"busy":@(_busy), @"phase":_phase?:@"idle", @"error":_error?:@""}; } }
- (void)cancel {
    @synchronized(self) { ++_serial; _phase = _busy ? @"cancelled" : @"idle"; _busy = NO; _error = @""; if (_pid > 1) kill(_pid, SIGKILL); _pid = 0; }
}
- (void)recordFailure:(NSString *)message {
    [self cancel];
    @synchronized(self) { _phase = @"failed"; _error = [message copy]; }
}
- (NSDictionary *)runHelper:(NSUInteger)serial {
    @synchronized(self) { if (serial != _serial) return nil; }
    int descriptors[2]; if (pipe(descriptors)) return @{@"ok":@NO, @"error":@"无法建立VPN启动通信。"};
    for (int index = 0; index < 2; index++) fcntl(descriptors[index], F_SETFD, FD_CLOEXEC);
    posix_spawn_file_actions_t actions; posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, descriptors[1], STDOUT_FILENO);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addclose(&actions, descriptors[0]); posix_spawn_file_actions_addclose(&actions, descriptors[1]);
    NSMutableDictionary *environment = [NSProcessInfo.processInfo.environment mutableCopy];
    // 独立系统控制助手不加载第三方UI插件，避免其启动代码影响后台连接。
    environment[@"_MSSafeMode"] = @"1"; environment[@"_SafeMode"] = @"1";
    NSMutableArray<NSString *> *entries = [NSMutableArray new];
    for (NSString *key in environment) [entries addObject:[NSString stringWithFormat:@"%@=%@", key, environment[key]]];
    char **values = calloc(entries.count + 1, sizeof(char *));
    if (!values) { posix_spawn_file_actions_destroy(&actions); close(descriptors[0]); close(descriptors[1]); return @{@"ok":@NO, @"error":@"无法准备VPN启动环境。"}; }
    for (NSUInteger index = 0; index < entries.count; index++) values[index] = (char *)entries[index].UTF8String;
    NSString *path = self.helperPath; char *arguments[] = {(char *)path.fileSystemRepresentation, "--connect", NULL}; pid_t child = 0;
    int code = posix_spawn(&child, path.fileSystemRepresentation, &actions, NULL, arguments, values);
    free(values); posix_spawn_file_actions_destroy(&actions); close(descriptors[1]);
    if (code) { close(descriptors[0]); return @{@"ok":@NO, @"error":@"无法启动系统VPN控制助手。"}; }
    @synchronized(self) { if (serial == _serial) _pid = child; else kill(child, SIGKILL); }
    fcntl(descriptors[0], F_SETFL, O_NONBLOCK);
    NSMutableData *data = [NSMutableData new]; double deadline = IHMonotonicTime() + 15; int status = 0; BOOL finished = NO, cancelled = NO, oversized = NO;
    while (IHMonotonicTime() < deadline) {
        char bytes[1024]; ssize_t size;
        while ((size = read(descriptors[0], bytes, sizeof(bytes))) > 0) { [data appendBytes:bytes length:(NSUInteger)size]; if (data.length > 4096) { oversized = YES; break; } }
        @synchronized(self) { cancelled = serial != _serial; }
        if (cancelled || oversized) break;
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) { finished = YES; break; }
        if (result < 0 && errno != EINTR) break;
        usleep(20000);
    }
    if (!finished) { kill(child, SIGKILL); while (waitpid(child, &status, 0) < 0 && errno == EINTR) {} }
    char bytes[1024]; ssize_t size;
    while ((size = read(descriptors[0], bytes, sizeof(bytes))) > 0 && data.length <= 4096) [data appendBytes:bytes length:(NSUInteger)size];
    close(descriptors[0]); @synchronized(self) { if (serial == _serial) _pid = 0; }
    if (cancelled) return nil;
    id value = data.length <= 4096 ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
    if (finished && [value isKindOfClass:NSDictionary.class]) {
        if (![value[@"ok"] boolValue]) return @{@"ok":@NO, @"error":[value[@"error"] isKindOfClass:NSString.class]?value[@"error"]:@"系统VPN连接失败。"};
        NSString *identifier = value[@"selectedServiceID"];
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && [identifier isKindOfClass:NSString.class] && [[NSUUID alloc] initWithUUIDString:identifier]) return value;
    }
    return @{@"ok":@NO, @"error":@"VPN未在期限内连接就绪，热点保持关闭。"};
}
- (BOOL)connectWithCompletion:(void (^)(NSDictionary *))completion {
    NSUInteger serial;
    @synchronized(self) { if (_busy || !self.supported) return NO; _busy = YES; _phase = @"connecting"; _error = @""; serial = ++_serial; }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ @autoreleasepool {
        NSDictionary *result = [self runHelper:serial];
        dispatch_async(dispatch_get_main_queue(), ^{
            @synchronized(self) { if (serial != self->_serial) return; self->_busy = NO; self->_phase = [result[@"ok"] boolValue] ? @"connected" : @"failed"; self->_error = result[@"error"] ?: @""; }
            if (completion) completion(result ?: @{@"ok":@NO, @"error":@"VPN连接已取消。"});
        });
    }});
    return YES;
}
@end
