#import <Foundation/Foundation.h>
#import "../common/IHNativeVPNProtocol.h"
#import "../common/IHNamedVPN16.h"
#include <notify.h>
#include <xpc/xpc.h>
#include <dlfcn.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

// 选择文件只能由root守护进程原子写入；缺失或enabled=false时完全调用原函数。
#define IHRuntimePath IHSourceRuntimePath.fileSystemRepresentation
static NSString *IHDiagnosticPath;
static BOOL IHUSBProcess;
static Boolean (*IHOriginalStart)(void *,const char *,int,unsigned int,xpc_object_t);
static BOOL IHHookInstalled;
// 供本地诊断核对当前加载代码；不触发重复安装或改写网络。
__attribute__((visibility("default"))) const char *IHSourceHookBuildIdentity(void){return IHSourcePolicyBuild;}
__attribute__((visibility("default"))) BOOL IHSourceHookIsInstalled(void){return IHHookInstalled;}

static BOOL IHValidInterface(NSString *name){
 if(![name isKindOfClass:NSString.class]||!name.length||name.length>=IFNAMSIZ)return NO;
 NSCharacterSet *bad=[[NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"] invertedSet];
 return [name rangeOfCharacterFromSet:bad].location==NSNotFound;
}
static NSString *IHSafeExternal(const char *value){
 if(!value)return @"";size_t size=strnlen(value,IFNAMSIZ);if(size>=IFNAMSIZ)return @"<invalid>";
 NSString *text=[[NSString alloc]initWithBytes:value length:size encoding:NSUTF8StringEncoding];return IHValidInterface(text)?text:@"<invalid>";
}
static void IHWriteDiagnostic(NSString *source,NSString *iface,NSString *original,NSString *selected,NSString *result){
 @autoreleasepool{
  // 不保存整个调用参数、原始XPC对象、热点密码、SSID、客户端或流量内容。
  NSString *nonce=[source isEqual:@"vpn"]?IHNativeReadJSON(IHSourceRuntimePath)[@"nativeSession"]:@"";
  NSDictionary *value=@{@"source":source?:@"",@"interface":iface?:@"",@"originalExternal":original?:@"",@"newExternal":selected?:@"",@"apiResult":result?:@"",@"sessionNonce":nonce?:@"",@"build":@(IHSourcePolicyBuild),@"packageVersion":@(IH_BUILD_VERSION),@"named16":@YES,@"hookInstalled":@(IHHookInstalled),@"pid":@(getpid()),@"process":NSProcessInfo.processInfo.processName,@"time":@(NSDate.date.timeIntervalSince1970)};
  NSData *data=[NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingSortedKeys error:NULL];if(!data)return;
  NSString *temporary=[IHDiagnosticPath stringByAppendingFormat:@".%d.%@.tmp",getpid(),NSUUID.UUID.UUIDString];
  int fd=open(temporary.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);if(fd<0)return;
  const unsigned char *bytes=data.bytes;size_t left=data.length;BOOL okay=YES;
  while(left){ssize_t wrote=write(fd,bytes,left);if(wrote<0&&errno==EINTR)continue;if(wrote<=0){okay=NO;break;}bytes+=wrote;left-=(size_t)wrote;}
  if(fchown(fd,0,0)!=0||fchmod(fd,0600)!=0)okay=NO;close(fd);
  if(!okay||rename(temporary.fileSystemRepresentation,IHDiagnosticPath.fileSystemRepresentation)!=0)unlink(temporary.fileSystemRepresentation);
 }
}
static NSDictionary *IHReadRuntime(BOOL *present,NSString **failure){
 *present=NO;int fd=open(IHRuntimePath,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
 if(fd<0){if(errno==ENOENT)return nil;*present=YES;*failure=@"runtimeOpenRejected";return nil;}
 *present=YES;struct stat st;if(fstat(fd,&st)!=0||!S_ISREG(st.st_mode)||st.st_uid!=0||(st.st_mode&0777)!=0600||st.st_nlink!=1||st.st_size<2||st.st_size>4096){close(fd);*failure=@"runtimeFileRejected";return nil;}
 NSMutableData *data=[NSMutableData dataWithLength:(NSUInteger)st.st_size];size_t position=0;
 while(position<data.length){ssize_t n=read(fd,(char*)data.mutableBytes+position,data.length-position);if(n<0&&errno==EINTR)continue;if(n<=0){close(fd);*failure=@"runtimeReadRejected";return nil;}position+=(size_t)n;}
 close(fd);id object=[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
 if(![object isKindOfClass:NSDictionary.class]){*failure=@"runtimeJSONRejected";return nil;}
 NSDictionary *runtime=object;id enabled=runtime[@"enabled"];
 if(![enabled isKindOfClass:NSNumber.class]||([enabled doubleValue]!=0&&[enabled doubleValue]!=1)){*failure=@"runtimeEnabledRejected";return nil;}
 // 明确停用优先，停用不依赖其他字段是否存在，保证禁用后原样通过。
 if(![enabled boolValue])return runtime;
 if(![runtime[@"version"] isKindOfClass:NSNumber.class]||[runtime[@"version"] integerValue]!=1||[runtime[@"version"] doubleValue]!=1){*failure=@"runtimeVersionRejected";return nil;}
 struct timeval boot={0};size_t bootSize=sizeof(boot);int mib[2]={CTL_KERN,KERN_BOOTTIME};
 if(sysctl(mib,2,&boot,&bootSize,NULL,0)!=0||st.st_mtimespec.tv_sec<boot.tv_sec){*failure=@"runtimePreviousBootRejected";return nil;}
 return runtime;
}
static BOOL IHUpstreamReady(NSString *name){
 struct ifaddrs *head=NULL;if(getifaddrs(&head)!=0)return NO;BOOL ready=NO;
 for(struct ifaddrs *p=head;p;p=p->ifa_next){
  if(!p->ifa_addr||strcmp(p->ifa_name,name.UTF8String)||!(p->ifa_flags&IFF_UP)||!(p->ifa_flags&IFF_RUNNING)||(p->ifa_flags&IFF_LOOPBACK))continue;
  if(p->ifa_addr->sa_family==AF_INET){uint32_t a=ntohl(((struct sockaddr_in*)p->ifa_addr)->sin_addr.s_addr);if(a&&a!=INADDR_BROADCAST&&(a>>24)!=127&&(a>>16)!=0xa9fe)ready=YES;}
  if(p->ifa_addr->sa_family==AF_INET6){struct in6_addr a=((struct sockaddr_in6*)p->ifa_addr)->sin6_addr;if(!IN6_IS_ADDR_UNSPECIFIED(&a)&&!IN6_IS_ADDR_LOOPBACK(&a)&&!IN6_IS_ADDR_LINKLOCAL(&a)&&!IN6_IS_ADDR_MULTICAST(&a))ready=YES;}
 }
 freeifaddrs(head);return ready;
}
static Boolean IHStart(void *client,const char *external,int mode,unsigned int bridge,xpc_object_t parameters){
 @autoreleasepool{
  if(!IHOriginalStart)return false;
  // Wi-Fi与USB沿用同一个旧客户端入口；USB额外验证真实驱动身份。
  if((mode!=200&&mode!=201)||!parameters||xpc_get_type(parameters)!=XPC_TYPE_DICTIONARY)return IHOriginalStart(client,external,mode,bridge,parameters);
  const char *internal=xpc_dictionary_get_string(parameters,"interfaceName");
  if(!internal||!IHValidInterface(@(internal)))return IHOriginalStart(client,external,mode,bridge,parameters);
  uint64_t deviceType=xpc_dictionary_get_uint64(parameters,"deviceType");
  BOOL wifi=!IHUSBProcess&&!strncmp(internal,"ap",2)&&deviceType==3;
  BOOL usb=IHUSBProcess&&deviceType==5&&IH16USBPort(@(internal));
  if(!wifi&&!usb)return IHOriginalStart(client,external,mode,bridge,parameters);
  BOOL present=NO;NSString *failure=nil;NSDictionary *runtime=IHReadRuntime(&present,&failure);
  if(!present|| (runtime&&![runtime[@"enabled"] boolValue]))return IHOriginalStart(client,external,mode,bridge,parameters);
  NSString *original=IHSafeExternal(external);
  if(!runtime){IHWriteDiagnostic(@"",@"ap1",original,@"",failure?:@"runtimeRejected");return false;}
  NSString *source=runtime[@"source"];
  if([source isKindOfClass:NSString.class]&&[source isEqual:@"cellular"])return IHOriginalStart(client,external,mode,bridge,parameters);
  NSString *upstream=runtime[@"upstream"];
  // 仅用已实测的系统原生路由/NAT；不创建PF规则、不route-to、不搬运报文。
  if([source isKindOfClass:NSString.class]&&[source isEqual:@"vpn"]){
   if(![runtime[@"kernelBackendVersion"] isEqual:@4]){IHWriteDiagnostic(@"vpn",@(internal),original,@"",@"legacyAuthorizationVersionRejected");return false;}
   {
    NSDictionary *session=IH16ActiveSession();
    if(!session){IHWriteDiagnostic(@"vpn",@(internal),original,@"",@"legacySessionNotReady");if([runtime[@"allowLegacyStart"] boolValue])notify_post(IH16StartNotification);return false;}
    // 开启AP会短暂重配上游；仅等待本轮授权收敛，后续严格检查照常执行。
    if(mode==201){
     double deadline=IHMonotonicTime()+2.5;
     do{
      NSDictionary *current=IH16ActiveSession();
      if(![current[@"nonce"] isEqual:session[@"nonce"]])break;
      if(IH16IdentityMatches(current[@"binding"])&&IH16RoutesMatch(current[@"binding"]))break;
      usleep(50000);
     }while(IHMonotonicTime()<deadline);
     session=IH16ActiveSession();
     if(!session){IHWriteDiagnostic(@"vpn",@(internal),original,@"",@"legacySessionNotReady");return false;}
    }
    NSString *selected=session[@"binding"][@"interface"],*transport=usb?@"usb":@"wifi",*prefix=session[@"prefixes"][transport]?:session[@"prefix"];
    NSDictionary *subnet=session[@"ipv4Subnets"][transport];
    if(!subnet){IHWriteDiagnostic(@"vpn",@(internal),original,@"",@"legacySubnetAuthorizationRejected");return false;}
    xpc_object_t scoped=xpc_copy(parameters);xpc_dictionary_set_string(scoped,"interfaceIPv4Address",[subnet[@"address"] UTF8String]);xpc_dictionary_set_string(scoped,"networkMask",[subnet[@"mask"] UTF8String]);xpc_dictionary_set_string(scoped,"startAddress",[subnet[@"start"] UTF8String]);xpc_dictionary_set_string(scoped,"endAddress",[subnet[@"end"] UTF8String]);
    void *image=dlopen(NULL,RTLD_NOW);const char **natSymbol=image?dlsym(image,"netrbClientNat66Param"):NULL,**prefixSymbol=image?dlsym(image,"netrbClientRaPrefix"):NULL;
    if(session&&!IHNativeIPv6Enabled(session)){
     BOOL valid=mode==201&&[selected isEqual:upstream]&&natSymbol&&IHNativeBindingMatches(session[@"binding"],IHKernelVPNBinding(),NO)&&IHKernelRoutesMatch([session[@"binding"][@"interfaceIndex"] unsignedIntValue],NO);
     if(!valid){IHWriteDiagnostic(@"vpn",@(internal),original,@"",@"vpnIPv4AuthorizationRejected");return false;}
     xpc_object_t copy=xpc_copy(scoped);xpc_dictionary_set_value(copy,*natSymbol,NULL);
     Boolean accepted=IHOriginalStart(client,selected.UTF8String,mode,bridge,copy);
     IHWriteDiagnostic(@"vpn",@(internal),original,selected,accepted?@"accepted":@"rejected");return accepted;
    }
    struct in6_addr network={0};NSArray *parts=[prefix componentsSeparatedByString:@"/"];
    BOOL valid=mode==201&&session&&[selected isEqual:upstream]&&IH16IdentityMatches(session[@"binding"])&&natSymbol&&prefixSymbol&&parts.count==2&&[parts[1] isEqual:@"64"]&&inet_pton(AF_INET6,[parts[0] UTF8String],&network)==1&&network.s6_addr[0]==0xfd;
    if(!valid){IHWriteDiagnostic(@"vpn",@(internal),original,@"",@"vpnNamed16AuthorizationRejected");return false;}
    xpc_object_t copy=xpc_copy(scoped),nat=xpc_dictionary_create(NULL,NULL,0);
    network.s6_addr[15]=1;char gateway[INET6_ADDRSTRLEN];if(!inet_ntop(AF_INET6,&network,gateway,sizeof(gateway)))return false;
    xpc_dictionary_set_string(copy,"interfaceIPv6Address",gateway);
    xpc_dictionary_set_string(nat,*prefixSymbol,[parts[0] UTF8String]);xpc_dictionary_set_value(copy,*natSymbol,nat);
    Boolean accepted=IHOriginalStart(client,selected.UTF8String,mode,bridge,copy);
    IHWriteDiagnostic(@"vpn",@(internal),original,selected,accepted?@"accepted":@"rejected");return accepted;
   }
  }
  if(![source isKindOfClass:NSString.class]||![source isEqual:@"wifi"]||!IHValidInterface(upstream)||![upstream isEqual:@"en0"]||!IHUpstreamReady(upstream)){
   IHWriteDiagnostic([source isKindOfClass:NSString.class]&&[@[@"wifi",@"vpn",@"cellular"] containsObject:source]?source:@"",@"ap1",original,@"",@"upstreamRejected");return false;
  }
  // 由misd的具名Wi-Fi控制面固定en0，进入原生前缀共享分支，不激活蜂窝。
  NSDictionary *misd=IHNativeReadJSON(IH16MisdState);
  if(![misd[@"sourcePolicyBuild"] isEqual:@(IHSourcePolicyBuild)]||![misd[@"wifiPrefixReady"] boolValue]||!IHNativeProcess([misd[@"pid"] intValue],"misd")){IHWriteDiagnostic(@"wifi",@(internal),original,@"",@"nativeWiFiPrefixNotReady");return false;}
  xpc_object_t copy=xpc_copy(parameters);xpc_dictionary_set_value(copy,"nat66Param",NULL);
  Boolean accepted=IHOriginalStart(client,NULL,mode,bridge,copy);
  IHWriteDiagnostic(@"wifi",@"ap1",original,upstream,accepted?@"accepted":@"rejected");return accepted;
 }
}
__attribute__((constructor)) static void IHInstallSourceHook(void){
 @autoreleasepool{
  NSString *process=NSProcessInfo.processInfo.processName;IHUSBProcess=[process isEqual:@"UserEventAgent"];
  if(!IHUSBProcess&&![process isEqual:@"wifid"])return;
  IHDiagnosticPath=IHUSBProcess?IHUSBSourceHookPath:IHSourceHookPath;
  void *image=dlopen(IHUSBProcess?"/System/Library/PrivateFrameworks/Netrb.framework/Netrb":NULL,RTLD_NOW);void *target=image?dlsym(image,"_NETRBClientStartService"):NULL;Dl_info info={0};
  const char *expected=IHUSBProcess?"/System/Library/PrivateFrameworks/Netrb.framework/Netrb":"/usr/sbin/wifid";
  if(!target||!dladdr(target,&info)||!info.dli_fname||strcmp(info.dli_fname,expected)){
   IHWriteDiagnostic(@"",@"",@"",@"",@"ownWifidSymbolRejected");return;
  }
  void (*hook)(void*,void*,void**)=dlsym(RTLD_DEFAULT,"MSHookFunction");
  if(!hook){void *substrate=dlopen(IHJailbreakPath(@"/usr/lib/libsubstrate.dylib").fileSystemRepresentation,RTLD_NOW);if(substrate)hook=dlsym(substrate,"MSHookFunction");}
  if(!hook){IHWriteDiagnostic(@"",@"",@"",@"",@"hookRuntimeUnavailable");return;}
  hook(target,(void*)&IHStart,(void**)&IHOriginalStart);IHHookInstalled=IHOriginalStart!=NULL;
  IHWriteDiagnostic(@"",@"",@"",@"",IHHookInstalled?@"ready":@"hookInstallFailed");
 }
}
