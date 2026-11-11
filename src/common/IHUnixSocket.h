#pragma once
#import <Foundation/Foundation.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

typedef struct {
    int socketFD, directoryFD, result, error;
    const char *name;
    BOOL binding;
} IHUnixSocketContext;

// Apple的线程局部目录接口；只在独立短生命周期线程使用，不改变宿主进程工作目录。
static void *IHUnixSocketWorker(void *value) {
    IHUnixSocketContext *context = value;
    int (*threadDirectory)(int) = dlsym(RTLD_DEFAULT, "pthread_fchdir_np");
    context->result = -1;
    if (!threadDirectory) { context->error = ENOTSUP; return NULL; }
    if (threadDirectory(context->directoryFD)) { context->error = errno; return NULL; }
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strlcpy(address.sun_path, context->name, sizeof(address.sun_path));
    context->result = context->binding ? bind(context->socketFD, (struct sockaddr *)&address, sizeof(address)) : connect(context->socketFD, (struct sockaddr *)&address, sizeof(address));
    context->error = errno;
    threadDirectory(-1);
    return NULL;
}
static int IHUnixSocketOperation(int fd, NSString *path, BOOL binding) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (path.length == 0) { errno = EINVAL; return -1; }
    if (strlen(path.fileSystemRepresentation) < sizeof(address.sun_path)) {
        strlcpy(address.sun_path, path.fileSystemRepresentation, sizeof(address.sun_path));
        return binding ? bind(fd, (struct sockaddr *)&address, sizeof(address)) : connect(fd, (struct sockaddr *)&address, sizeof(address));
    }
    // sockaddr_un只有短路径缓冲区；以libroot目录fd为基准使用相对名称，文件仍在原目录。
    NSString *name = path.lastPathComponent;
    if (strlen(name.fileSystemRepresentation) >= sizeof(address.sun_path)) { errno = ENAMETOOLONG; return -1; }
    int directory = open(path.stringByDeletingLastPathComponent.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) return -1;
    IHUnixSocketContext context = {.socketFD = fd, .directoryFD = directory, .name = name.fileSystemRepresentation, .binding = binding};
    pthread_t worker; int code = pthread_create(&worker, NULL, IHUnixSocketWorker, &context);
    if (code) { close(directory); errno = code; return -1; }
    pthread_join(worker, NULL); close(directory); errno = context.error;
    return context.result;
}
