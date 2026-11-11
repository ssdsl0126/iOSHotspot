#import "../common/IHPaths.h"
#import "../common/IHProtocol.h"
#import "../common/IHTimeouts.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <signal.h>

static BOOL IHPathError(NSError **error, NSString *message) {
    if (error) *error = [NSError errorWithDomain:@"iOSHotspot.Paths" code:1 userInfo:@{NSLocalizedDescriptionKey:message}];
    return NO;
}
static BOOL IHPrepareDirectory(NSString *path, mode_t mode, NSError **error) {
    struct stat info;
    if (lstat(path.fileSystemRepresentation, &info) == 0 && (!S_ISDIR(info.st_mode) || info.st_uid != geteuid())) return IHPathError(error, @"项目目录类型或所有者不正确。");
    if (![NSFileManager.defaultManager createDirectoryAtPath:path withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions:@(mode)} error:error]) return NO;
    if (chmod(path.fileSystemRepresentation, mode)) return IHPathError(error, @"无法设置项目目录权限。");
    return YES;
}
static BOOL IHWritePathData(NSData *data, NSString *path, mode_t mode, NSError **error) {
    NSString *temporary = [path stringByAppendingFormat:@".%d.%@.tmp", getpid(), NSUUID.UUID.UUIDString];
    int fd = open(temporary.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
    if (fd < 0) return IHPathError(error, @"无法创建项目临时文件。");
    size_t offset = 0; BOOL okay = YES;
    while (offset < data.length) {
        ssize_t count = write(fd, (const char *)data.bytes + offset, data.length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { okay = NO; break; }
        offset += (size_t)count;
    }
    if (fchmod(fd, mode) || fsync(fd)) okay = NO;
    close(fd);
    if (okay && rename(temporary.fileSystemRepresentation, path.fileSystemRepresentation) == 0) return YES;
    unlink(temporary.fileSystemRepresentation);
    return IHPathError(error, @"项目文件原子写入失败，原文件已保留。");
}
static BOOL IHPreparePaths(NSError **error) {
    // 新命名空间独立保存配置和会话，不读取、迁移或清理旧目录。
    if (!IHPrepareDirectory(IHDataDirectory, 0700, error) || !IHPrepareDirectory(IHRuntimeDirectory, 0755, error) || !IHPrepareDirectory(IHLogDirectory, 0700, error)) return NO;
    int fd = open(IHServiceLogPath.fileSystemRepresentation, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return IHPathError(error, @"无法创建服务日志。");
    BOOL okay = fchmod(fd, 0600) == 0; close(fd); if (!okay) return IHPathError(error, @"无法设置日志权限。");
    return YES;
}
static BOOL IHInstallLaunchDaemon(NSError **error) {
    NSString *path = IHJailbreakPath(@"/Library/LaunchDaemons/com.newbie.ioshotspot.plist");
    NSMutableDictionary *value = [[NSDictionary dictionaryWithContentsOfFile:path] mutableCopy];
    if (!value) return IHPathError(error, @"无法读取服务模板。");
    value[@"ProgramArguments"] = @[IHJailbreakPath(@"/usr/libexec/ioshotspotd")];
    value[@"StandardOutPath"] = IHServiceLogPath; value[@"StandardErrorPath"] = IHServiceLogPath;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:value format:NSPropertyListXMLFormat_v1_0 options:0 error:error];
    return data && IHWritePathData(data, path, 0644, error);
}
static BOOL IHHookLoaded(NSString *path, const char *process) {
    struct stat info;
    if (lstat(path.fileSystemRepresentation, &info) || !S_ISREG(info.st_mode) || info.st_uid || (info.st_mode & 0777) != 0600 || info.st_size > 32768) return NO;
    NSData *data = [NSData dataWithContentsOfFile:path];
    NSDictionary *value = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
    if (![value isKindOfClass:NSDictionary.class] || ![value[@"packageVersion"] isEqual:@(IH_BUILD_VERSION)]) return NO;
    int (*processName)(int, void *, uint32_t) = dlsym(RTLD_DEFAULT, "proc_name");
    pid_t pid = [value[@"pid"] intValue]; char name[64] = {0};
    return pid > 1 && kill(pid, 0) == 0 && processName && processName(pid, name, sizeof(name)) > 0 && !strcmp(name, process);
}
static BOOL IHVerifyHooks(void) {
    BOOL wifi = NO, usb = NO, misd = NO;
    // 安装期短暂检查实际加载版本；运行期不增加常驻轮询。
    for (NSUInteger attempt = 0; attempt < 60; attempt++) {
        wifi = IHHookLoaded(IHSourceHookPath, "wifid");
        usb = IHHookLoaded(IHUSBSourceHookPath, "UserEventAgent");
        misd = IHHookLoaded(IH16MisdState, "misd");
        if (wifi && usb && misd) { puts("iOSHotspot: all three hook hosts loaded the installed version"); return YES; }
        usleep(250000);
    }
    fprintf(stderr, "iOSHotspot hook load check failed: wifid=%d UserEventAgent=%d misd=%d\n", wifi, usb, misd);
    return NO;
}
static BOOL IHVerifyService(void) {
    double deadline = IHMonotonicTime() + 15;
    do {
        NSDictionary *status = IHRequest(@{@"command":@"status"}, NULL);
        if ([status[@"ok"] boolValue] && [status[@"version"] isEqual:@(IH_BUILD_VERSION)]) {
            puts("iOSHotspot: installed daemon version responds through libroot IPC"); return YES;
        }
        usleep(250000);
    } while (IHMonotonicTime() < deadline);
    fprintf(stderr, "iOSHotspot: installed daemon failed its IPC readiness check\n"); return NO;
}
int main(int argc, char **argv) { @autoreleasepool {
    umask(0077); NSError *error = nil;
    if (argc == 3 && !strcmp(argv[1], "resolve")) {
        NSString *path = @(argv[2]);
        if (![path hasPrefix:@"/"] || [path.pathComponents containsObject:@".."]) return 2;
        puts(IHJailbreakPath(path).fileSystemRepresentation); return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "describe")) {
        NSDictionary *paths = @{@"data":IHDataDirectory, @"runtime":IHRuntimeDirectory, @"log":IHServiceLogPath, @"socket":IHSocketPath};
        NSData *data = [NSJSONSerialization dataWithJSONObject:paths options:NSJSONWritingPrettyPrinted error:nil]; fwrite(data.bytes, 1, data.length, stdout); putchar('\n'); return 0;
    }
    if (geteuid() != 0) return 2;
    if (argc == 2 && !strcmp(argv[1], "prepare")) {
        if (IHPreparePaths(&error) && IHInstallLaunchDaemon(&error)) return 0;
        fprintf(stderr, "%s\n", error.localizedDescription.UTF8String); return 1;
    }
    if (argc == 2 && !strcmp(argv[1], "verify-hooks")) return IHVerifyHooks() ? 0 : 1;
    if (argc == 2 && !strcmp(argv[1], "verify-service")) return IHVerifyService() ? 0 : 1;
    return 2;
} }
