#pragma once
#import <Foundation/Foundation.h>
#import "IHKernelVPN.h"
#import "IHKernelRoute.h"
#import "IHTimeouts.h"
#import "IHPaths.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <spawn.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <errno.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
extern char **environ;

static const char *IHNativeNotification="com.newbie.ioshotspot.native-vpn-state";
static const char *IHSourcePolicyBuild="native-wifi-prefix-v1";

// 缺少选项时默认IPv4单栈，不自动开启IPv6共享。
static BOOL IHNativeIPv6Enabled(NSDictionary *value){return [value[@"vpnIPv6"] boolValue];}
static BOOL IHNativeBindingMatches(NSDictionary *expected,NSDictionary *current,BOOL ipv6){
 if(ipv6)return IHKernelVPNMatches(expected,current);
 if(!expected.count||!current.count)return NO;
 for(NSString *key in @[@"interface",@"interfaceIndex",@"serviceID",@"ipv4addresses",@"dnsServers"])if(![expected[key] isEqual:current[key]])return NO;
 return YES;
}

static BOOL IHNativeInterfaceName(NSString *name){
 if(![name isKindOfClass:NSString.class]||!name.length||name.length>=IFNAMSIZ)return NO;
 return [name rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"].invertedSet].location==NSNotFound;
}
static NSDictionary *IHNativeReadJSONChecked(NSString *path,NSDictionary **failure){
 for(unsigned attempt=0;attempt<3;attempt++){
 int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0){if(failure)*failure=@{@"check":@"open",@"errno":@(errno)};return nil;}
 struct stat st={0};int code=fstat(fd,&st);
 // 原子替换可在open与fstat之间解除旧文件链接；只重开当前路径，不接受旧描述符。
 BOOL replaced=!code&&S_ISREG(st.st_mode)&&!st.st_uid&&(st.st_mode&0777)==0600&&!st.st_nlink&&st.st_size>=2&&st.st_size<=32768;
 if(replaced&&attempt<2){close(fd);continue;}
 if(code||!S_ISREG(st.st_mode)||st.st_uid||(st.st_mode&0777)!=0600||st.st_nlink!=1||st.st_size<2||st.st_size>32768){if(failure)*failure=@{@"check":@"metadata",@"mode":@(st.st_mode&0777),@"links":@(st.st_nlink),@"uid":@(st.st_uid),@"size":@(st.st_size)};close(fd);return nil;}
 NSMutableData *data=[NSMutableData dataWithLength:(NSUInteger)st.st_size];size_t offset=0;
 while(offset<data.length){ssize_t count=read(fd,(char*)data.mutableBytes+offset,data.length-offset);if(count<0&&errno==EINTR)continue;if(count<=0){close(fd);return nil;}offset+=(size_t)count;}close(fd);
 id value=[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];return [value isKindOfClass:NSDictionary.class]?value:nil;
 }return nil;
}
static NSDictionary *IHNativeReadJSON(NSString *path){return IHNativeReadJSONChecked(path,NULL);}
static BOOL IHNativeWriteJSONValue(NSString *path,NSDictionary *value,BOOL durable){
 NSData *data=[NSJSONSerialization dataWithJSONObject:value options:0 error:NULL];if(!data||data.length>32768)return NO;
 NSString *temporary=[path stringByAppendingFormat:@".%d.%@.tmp",getpid(),NSUUID.UUID.UUIDString];
 int fd=open(temporary.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)return NO;
 size_t offset=0;BOOL okay=YES;
 while(offset<data.length){ssize_t count=write(fd,(const char*)data.bytes+offset,data.length-offset);if(count<0&&errno==EINTR)continue;if(count<=0){okay=NO;break;}offset+=(size_t)count;}
 if(fchmod(fd,0600)||(durable&&fsync(fd)))okay=NO;close(fd);
 if(okay&&rename(temporary.fileSystemRepresentation,path.fileSystemRepresentation)==0)return YES;
 unlink(temporary.fileSystemRepresentation);return NO;
}
// 授权和恢复日志持久化；可重建状态仍原子替换，但不在系统回调内等待磁盘同步。
static BOOL IHNativeWriteJSON(NSString *path,NSDictionary *value){return IHNativeWriteJSONValue(path,value,YES);}
static BOOL IHNativeWriteRuntimeJSON(NSString *path,NSDictionary *value){return IHNativeWriteJSONValue(path,value,NO);}
static BOOL IHNativeProcess(pid_t pid,const char *expected){
 int(*processName)(int,void*,uint32_t)=dlsym(RTLD_DEFAULT,"proc_name");char name[64]={0};
 return pid>1&&kill(pid,0)==0&&processName&&processName(pid,name,sizeof(name))>0&&!strcmp(name,expected);
}
static NSDictionary *IHNativeEntities(NSDictionary *binding){
 NSString *service=binding[@"serviceID"];if(![service isKindOfClass:NSString.class]||!service.length)return @{};
 NSMutableDictionary *values=[NSMutableDictionary new];for(NSString *entity in @[@"IPv4",@"IPv6",@"DNS"]){NSString *key=[NSString stringWithFormat:@"State:/Network/Service/%@/%@",service,entity];values[key]=IHKernelVPNStore(key);}return values;
}
static NSDictionary *IHNativeEntitiesForMode(NSDictionary *binding,BOOL ipv6){
 if(ipv6)return IHNativeEntities(binding);
 NSMutableDictionary *values=[NSMutableDictionary new];NSString *service=binding[@"serviceID"];
 for(NSString *entity in @[@"IPv4",@"DNS"]){NSString *key=[NSString stringWithFormat:@"State:/Network/Service/%@/%@",service,entity];values[key]=IHKernelVPNStore(key);}return values;
}
static BOOL IHNativeBindingValid(NSDictionary *session){
 NSDictionary *binding=session[@"binding"],*entities=session[@"entities"];NSString *name=binding[@"interface"];
 BOOL ipv6=IHNativeIPv6Enabled(session);
 if(!IHKernelVPNName(name)||!if_nametoindex(name.UTF8String)||if_nametoindex(name.UTF8String)!=[binding[@"interfaceIndex"] unsignedIntValue]||entities.count!=(ipv6?3:2))return NO;
 for(NSString *key in entities)if(![entities[key] isEqual:IHKernelVPNStore(key)])return NO;
 return IHKernelRoutesMatch([binding[@"interfaceIndex"] unsignedIntValue],ipv6&&[binding[@"ipv6addresses"] count]>0);
}
static NSDictionary *IHNativeFamilyPolicySession(void){
 NSDictionary *session=IHNativeReadJSON(IHNativeSessionPath),*state=IHNativeReadJSON(IHNativeStatePath),*runtime=IHNativeReadJSON(IHSourceRuntimePath);
 if(!session.count||![runtime[@"enabled"] boolValue]||![runtime[@"source"] isEqual:@"vpn"]||![runtime[@"nativeSession"] isEqual:session[@"nonce"]]||![state[@"nonce"] isEqual:session[@"nonce"]])return nil;
 if([session[@"parentPID"] intValue]<=1||[state[@"parentPID"] intValue]!=[session[@"parentPID"] intValue]||IHNativeIPv6Enabled(runtime)!=IHNativeIPv6Enabled(session))return nil;
 // 此函数只收紧IPv6门控；进程退出到清理完成之间仍按可信root会话记录保持阻断。
 return session;
}
static int IHNativeSetForwarding(int family,int value){return sysctlbyname(family==AF_INET?"net.inet.ip.forwarding":"net.inet6.ip6.forwarding",NULL,NULL,&value,sizeof(value));}
static NSString *IHNativeIfconfigUntil(NSArray<NSString*> *arguments,double deadline,NSError **error){
 if(IHMonotonicTime()>=deadline){if(error)*error=[NSError errorWithDomain:NSPOSIXErrorDomain code:ETIMEDOUT userInfo:@{NSLocalizedDescriptionKey:@"原生网络清理已超时，保留恢复日志。"}];return nil;}
 NSString *binary=nil;for(NSString *path in @[IHJailbreakPath(@"/sbin/ifconfig"),IHJailbreakPath(@"/usr/sbin/ifconfig")])if(access(path.fileSystemRepresentation,X_OK)==0){binary=path;break;}
 if(!binary){if(error)*error=[NSError errorWithDomain:NSPOSIXErrorDomain code:ENOENT userInfo:@{NSLocalizedDescriptionKey:@"找不到系统 ifconfig，无法管理原生网桥。"}];return nil;}
 int pipes[2];if(pipe(pipes))return nil;
 fcntl(pipes[0],F_SETFD,FD_CLOEXEC);fcntl(pipes[1],F_SETFD,FD_CLOEXEC);
 posix_spawn_file_actions_t actions;posix_spawn_file_actions_init(&actions);posix_spawn_file_actions_adddup2(&actions,pipes[1],STDOUT_FILENO);posix_spawn_file_actions_adddup2(&actions,pipes[1],STDERR_FILENO);posix_spawn_file_actions_addclose(&actions,pipes[0]);posix_spawn_file_actions_addclose(&actions,pipes[1]);
 char *argv[10]={0};argv[0]=(char*)binary.fileSystemRepresentation;if(arguments.count>8){close(pipes[0]);close(pipes[1]);posix_spawn_file_actions_destroy(&actions);return nil;}
 for(NSUInteger index=0;index<arguments.count;index++)argv[index+1]=(char*)arguments[index].UTF8String;
 pid_t pid=0;int code=posix_spawn(&pid,binary.fileSystemRepresentation,&actions,NULL,argv,environ);posix_spawn_file_actions_destroy(&actions);close(pipes[1]);
 if(code){close(pipes[0]);if(error)*error=[NSError errorWithDomain:NSPOSIXErrorDomain code:code userInfo:nil];return nil;}
 fcntl(pipes[0],F_SETFL,O_NONBLOCK);NSMutableData *data=[NSMutableData data];double limit=MIN(deadline,IHMonotonicTime()+3);int status=0;BOOL finished=NO;
 while(IHMonotonicTime()<limit){char buffer[4096];ssize_t size;while((size=read(pipes[0],buffer,sizeof(buffer)))>0&&data.length<128*1024)[data appendBytes:buffer length:(NSUInteger)size];if(waitpid(pid,&status,WNOHANG)==pid){finished=YES;break;}usleep(10000);}
 if(!finished){kill(pid,SIGKILL);waitpid(pid,&status,0);}char buffer[4096];ssize_t size;while((size=read(pipes[0],buffer,sizeof(buffer)))>0&&data.length<128*1024)[data appendBytes:buffer length:(NSUInteger)size];close(pipes[0]);
 NSString *text=[[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]?:@"";
 if(!finished||!WIFEXITED(status)||WEXITSTATUS(status)){if(error)*error=[NSError errorWithDomain:@"com.newbie.ioshotspot.native" code:finished?WEXITSTATUS(status):ETIMEDOUT userInfo:@{NSLocalizedDescriptionKey:text.length?text:@"原生网桥命令未完成。"}];return nil;}return text;
}
static NSString *IHNativeIfconfig(NSArray<NSString*> *arguments,NSError **error){return IHNativeIfconfigUntil(arguments,IHMonotonicTime()+3,error);}
