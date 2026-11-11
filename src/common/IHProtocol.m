#import "IHProtocol.h"
#import "IHTimeouts.h"
#import "IHUnixSocket.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <math.h>
static BOOL IHWaitSocket(int fd, short events, double deadline) {
    for (;;) {
        double remaining = deadline - IHMonotonicTime();
        if (remaining <= 0) { errno = ETIMEDOUT; return NO; }
        struct pollfd descriptor = {.fd=fd, .events=events};
        int result = poll(&descriptor, 1, (int)ceil(remaining * 1000));
        if (result > 0) return YES;
        if (result == 0) { errno = ETIMEDOUT; return NO; }
        if (errno != EINTR) return NO;
    }
}
static NSDictionary *IHRequestAtPath(NSDictionary *request, NSString *path, double interval, NSError **error) {
    NSData *json = nil; NSMutableData *wire = nil; NSMutableData *received = nil; id value = nil;
    double deadline = IHMonotonicTime() + interval;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) goto fail;
    // 整个请求共用一个期限，连接、发送及分段接收都不能无限延期。
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) goto fail;
    int noSignal = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, sizeof(noSignal));
    if (IHUnixSocketOperation(fd, path, NO) != 0) {
        if (errno != EINPROGRESS && errno != EWOULDBLOCK) goto fail;
        if (!IHWaitSocket(fd, POLLOUT, deadline)) goto fail;
        int code = 0; socklen_t length = sizeof(code);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &code, &length) != 0) goto fail;
        if (code) { errno = code; goto fail; }
    }
    json = [NSJSONSerialization dataWithJSONObject:request options:0 error:error];
    if (!json || json.length > 16384) { close(fd); return nil; }
    wire = [json mutableCopy]; [wire appendBytes:"\n" length:1];
    size_t sent = 0;
    while (sent < wire.length) {
        if (!IHWaitSocket(fd, POLLOUT, deadline)) goto fail;
        ssize_t n = send(fd, (char *)wire.bytes + sent, wire.length - sent, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0) goto fail; sent += n;
    }
    shutdown(fd, SHUT_WR);
    received = [NSMutableData data]; char buffer[4096]; ssize_t n;
    for (;;) {
        if (!IHWaitSocket(fd, POLLIN, deadline)) goto fail;
        n = recv(fd, buffer, sizeof(buffer), 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n < 0) goto fail;
        if (!n) break;
        [received appendBytes:buffer length:n]; if (received.length > 1048576) { errno = EFBIG; goto fail; }
    }
    close(fd);
    value = [NSJSONSerialization JSONObjectWithData:received options:0 error:error];
    return [value isKindOfClass:NSDictionary.class] ? value : nil;
fail:
    { int code = errno; if(fd >= 0) close(fd); if(error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:code userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"无法连接热点服务：%s",strerror(code)]}]; return nil; }
}
NSDictionary *IHRequest(NSDictionary *request, NSError **error) {
    BOOL readOnly = [@[@"status", @"report"] containsObject:request[@"command"]];
    return IHRequestAtPath(request, IHSocketPath, readOnly ? IHStatusRequestTimeout : IHMutationRequestTimeout, error);
}
