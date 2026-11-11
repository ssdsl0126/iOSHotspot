#import "IHNetwork.h"
#import "../common/IHNamedVPN16.h"
#import "../common/IHVPNStartup.h"
#include <notify.h>
#include <arpa/inet.h>
#include <time.h>

static IHNetwork *radio;
static NSDictionary *session;
static NSString *prefix,*bridgeName,*failure;
static NSArray<NSString*> *bridgeNames;
static NSMutableArray<NSDictionary*> *ipv6Aliases;
static BOOL journal(void);
static double startupAt,radioRequestedAt,radioReturnedAt,readyAt;
static double monotonicTime(void){struct timespec value;clock_gettime(CLOCK_MONOTONIC,&value);return value.tv_sec+value.tv_nsec/1e9;}
static BOOL ensureIPv6Gateways(void){
 for(NSString *name in IH16SessionBridges(session)){
  NSString *prefix=IH16BridgePrefix(session,name);NSArray *parts=[prefix componentsSeparatedByString:@"/"];struct in6_addr address={0};
  if(parts.count!=2||inet_pton(AF_INET6,[parts[0] UTF8String],&address)!=1)return NO;address.s6_addr[15]=1;
  char text[INET6_ADDRSTRLEN];if(!inet_ntop(AF_INET6,&address,text,sizeof(text)))return NO;NSString *gateway=@(text);
  if(IH16HasIPv6Address(name,gateway))continue;
  NSDictionary *entry=@{@"interface":name,@"index":@(if_nametoindex(name.UTF8String)),@"address":gateway};if(![ipv6Aliases containsObject:entry])[ipv6Aliases addObject:entry];
  if(!journal()||!IHNativeIfconfig(@[name,@"inet6",gateway,@"prefixlen",@"64",@"alias"],NULL))return NO;
 }
 return YES;
}
static dispatch_queue_t watchQueue;
static dispatch_source_t routeSource,ownerTimer,termSource,intSource;
static dispatch_semaphore_t ended,readinessWake;
static int readinessToken=-1;
static SCDynamicStoreRef store,controlStore;
static int routeFD=-1,baseline4,baseline6;
static _Atomic bool ending=false,gateOpen=false,controlActive=false;
static NSDate *startedAt,*pausedAt;
static BOOL started;
static NSUInteger startupRetries;
static NSDictionary *authorizationFailure,*validationFailure;
static SCDynamicStoreRef(*createStore)(CFAllocatorRef,CFStringRef,SCDynamicStoreCallBack,SCDynamicStoreContext*);
static Boolean(*setKeys)(SCDynamicStoreRef,CFArrayRef,CFArrayRef),(*setQueue)(SCDynamicStoreRef,dispatch_queue_t);
static Boolean(*addTemporary)(SCDynamicStoreRef,CFStringRef,CFPropertyListRef),(*setValue)(SCDynamicStoreRef,CFStringRef,CFPropertyListRef),(*removeValue)(SCDynamicStoreRef,CFStringRef);

static void blockForwarding(void){IHNativeSetForwarding(AF_INET,0);IHNativeSetForwarding(AF_INET6,0);atomic_store(&gateOpen,false);}
static BOOL ownerValid(void){
 NSDictionary *readFailure=nil,*runtime=IHNativeReadJSONChecked(IHSourceRuntimePath,&readFailure);
 BOOL parent=IHNativeProcess([session[@"parentPID"] intValue],"ioshotspotd");
 BOOL valid=!atomic_load(&ending)&&parent&&[runtime[@"enabled"] boolValue]&&[runtime[@"source"] isEqual:@"vpn"]&&[runtime[@"nativeSession"] isEqual:session[@"nonce"]]&&IHNativeIPv6Enabled(runtime)==IHNativeIPv6Enabled(session);
 if(!valid&&!atomic_load(&ending))authorizationFailure=@{@"parentAlive":@(parent),@"runtimeRead":@(runtime!=nil),@"readFailure":readFailure?:@{},@"enabled":runtime[@"enabled"]?:@NO,@"source":runtime[@"source"]?:@"",@"runtimeNonce":runtime[@"nativeSession"]?:@"",@"sessionNonce":session[@"nonce"]?:@"",@"runtimeIPv6":@(IHNativeIPv6Enabled(runtime)),@"sessionIPv6":@(IHNativeIPv6Enabled(session))};
 return valid;
}
static BOOL validVPN(void){
 BOOL ipv6=IHNativeIPv6Enabled(session);if(!ownerValid())return NO;
 BOOL identity=ipv6?IH16IdentityMatches(session[@"binding"]):IHNativeBindingMatches(session[@"binding"],IHKernelVPNBinding(),NO);
 BOOL routes=identity&&IHKernelRoutesMatch([session[@"binding"][@"interfaceIndex"] unsignedIntValue],ipv6);
 if(!routes)validationFailure=@{@"time":@(NSDate.date.timeIntervalSince1970),@"identity":@(identity),@"expected":session[@"binding"],@"actual":IHNativeEntities(session[@"binding"]),@"currentBinding":IHKernelVPNBinding(),@"route4a":@(IHKernelRouteIndex(AF_INET,"1.1.1.1")),@"route4b":@(IHKernelRouteIndex(AF_INET,"200.1.1.1")),@"route6":@(IHKernelRouteIndex(AF_INET6,"2600:1901:0:13e0::"))};
 return routes;
}
static NSDictionary *controlValue(BOOL active){
 NSDictionary *entity=session[@"entities"][[NSString stringWithFormat:@"State:/Network/Service/%@/IPv6",session[@"binding"][@"serviceID"]]];
 return @{@"version":@1,@"backend":IH16Backend,@"active":@(active),@"vpnIPv6":@(IHNativeIPv6Enabled(session)),@"nonce":session[@"nonce"],@"time":@(NSDate.date.timeIntervalSince1970),@"interface":session[@"binding"][@"interface"],@"interfaceIndex":session[@"binding"][@"interfaceIndex"],@"addresses":entity[@"Addresses"]?:@[],@"prefixes":entity[@"PrefixLength"]?:@[]};
}
static BOOL publish(NSString *phase,BOOL radioReady){
 NSDictionary *value=@{@"backend":IH16Backend,@"phase":phase,@"pid":@(getpid()),@"parentPID":session[@"parentPID"],@"nonce":session[@"nonce"],@"radioReady":@(radioReady),@"gateOpen":@(atomic_load(&gateOpen)),@"vpnIPv6":@(IHNativeIPv6Enabled(session)),@"bridge":bridgeName?:@"",@"bridges":bridgeNames?:@[],@"bridgeIndex":@(bridgeName.length?if_nametoindex(bridgeName.UTF8String):0),@"prefix":prefix?:@"",@"moves":@[],@"error":failure?:@"",@"time":@(NSDate.date.timeIntervalSince1970)};
 NSMutableDictionary *record=[value mutableCopy];record[@"startupTimingMs"]=@{@"initialization":@(radioRequestedAt>0?(radioRequestedAt-startupAt)*1000:0),@"radioRequest":@(radioReturnedAt>0?(radioReturnedAt-radioRequestedAt)*1000:0),@"ready":@(readyAt>0?(readyAt-startupAt)*1000:0)};
 record[@"startupAttempts"]=@(startupRetries+1);if(authorizationFailure)record[@"authorizationFailure"]=authorizationFailure;if(validationFailure)record[@"validationFailure"]=validationFailure;
 BOOL okay=IHNativeWriteRuntimeJSON(IHNativeStatePath,record);
 if(controlStore&&setValue)okay=setValue(controlStore,(__bridge CFStringRef)IH16ControlKey,(__bridge CFDictionaryRef)controlValue(atomic_load(&controlActive)&&ownerValid()))&&okay;
 notify_post(IHNativeNotification);return okay;
}
static void requestStop(NSString *reason){
 if(atomic_exchange(&ending,true))return;failure=reason;atomic_store(&controlActive,false);blockForwarding();
 if(controlStore&&setValue)setValue(controlStore,(__bridge CFStringRef)IH16ControlKey,(__bridge CFDictionaryRef)controlValue(NO));dispatch_semaphore_signal(ended);
}
static void checkVPN(void){
 if(atomic_load(&ending))return;
 if(!IHNativeIPv6Enabled(session)&&IHKernelForwarding(AF_INET6)!=0){requestStop(@"IPv6转发状态异常，已阻断共享。");return;}
 if(validVPN()){
  if(started&&IHNativeIPv6Enabled(session)&&!ensureIPv6Gateways()){requestStop(@"无法维护本轮IPv6网关，已关闭共享。");return;}
  if(pausedAt){
   if(IHNativeSetForwarding(AF_INET,1)||IHNativeSetForwarding(AF_INET6,IHNativeIPv6Enabled(session)?1:0)){requestStop(@"无法恢复本会话的内核转发门控。");return;}
   atomic_store(&gateOpen,true);pausedAt=nil;if(!publish(@"running",YES))requestStop(@"无法保存VPN转发状态，已关闭共享。");
  }return;
 }
 blockForwarding();
 BOOL owner=ownerValid();unsigned actualIndex=if_nametoindex([session[@"binding"][@"interface"] UTF8String]);
 if(!owner||actualIndex!=[session[@"binding"][@"interfaceIndex"] unsignedIntValue]){if(owner)authorizationFailure=@{@"check":@"interfaceIndex",@"actual":@(actualIndex),@"expected":session[@"binding"][@"interfaceIndex"]};requestStop(@"VPN已断开或共享授权失效，已阻断转发并关闭热点。");return;}
 if(!startedAt||([NSDate.date timeIntervalSinceDate:startedAt]<20&&!started))return;
 if(!pausedAt){pausedAt=NSDate.date;publish(@"paused",YES);}
 // 同一授权、同一隧道的配置重发只暂停转发，保留无线连接。
 // SC/路由事件及唯一的每秒检查负责恢复，避免每次事件递归排队形成轮询风暴。
 // 恢复仍走上面的完整身份与路由检查；授权撤回或接口变化仍立即退出。
}
static void changed(SCDynamicStoreRef value,CFArrayRef keys,void *context){checkVPN();}
static BOOL watchVPN(void){
 createStore=dlsym(RTLD_DEFAULT,"SCDynamicStoreCreate");setKeys=dlsym(RTLD_DEFAULT,"SCDynamicStoreSetNotificationKeys");setQueue=dlsym(RTLD_DEFAULT,"SCDynamicStoreSetDispatchQueue");
 if(!createStore||!setKeys||!setQueue)return NO;
 store=createStore(NULL,CFSTR("iOSHotspotNamed16"),changed,NULL);
 // 就绪事件立即唤醒启动检查，轮询只兜底，不增加固定启动延时。
 if(notify_register_dispatch(IH16ReadyNotification,&readinessToken,watchQueue,^(int token){dispatch_semaphore_signal(readinessWake);})!=NOTIFY_STATUS_OK)readinessToken=-1;
 NSMutableArray *keys=[[session[@"entities"] allKeys] mutableCopy];for(NSString *family in @[@"IPv4",@"IPv6"]){[keys addObject:[NSString stringWithFormat:@"State:/Network/Interface/%@/%@",session[@"binding"][@"interface"],family]];[keys addObject:[@"State:/Network/Global/" stringByAppendingString:family]];}
 if(!store||!setKeys(store,(__bridge CFArrayRef)keys,NULL)||!setQueue(store,watchQueue))return NO;
 routeFD=socket(PF_ROUTE,SOCK_RAW,0);if(routeFD<0||fcntl(routeFD,F_SETFL,O_NONBLOCK))return NO;
 routeSource=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,routeFD,0,watchQueue);
 dispatch_source_set_event_handler(routeSource,^{
  uint8_t bytes[8192];ssize_t count;BOOL relevant=NO;
  while((count=read(routeFD,bytes,sizeof(bytes)))>0)for(size_t offset=0;offset+4<=(size_t)count;){uint16_t size;memcpy(&size,bytes+offset,2);if(size<4||size>(size_t)count-offset)break;
   if(bytes[offset+2]==5&&bytes[offset+3]!=4)relevant=YES;offset+=size;}
  if(relevant)checkVPN();
 });dispatch_resume(routeSource);
 // 路由/SC事件立即门控，活动期间每秒仅做父服务与授权的兜底检查。
 ownerTimer=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,watchQueue);dispatch_source_set_timer(ownerTimer,dispatch_time(DISPATCH_TIME_NOW,NSEC_PER_SEC),NSEC_PER_SEC,NSEC_PER_SEC/10);
 dispatch_source_set_event_handler(ownerTimer,^{checkVPN();});dispatch_resume(ownerTimer);return YES;
}
static BOOL serveControl(void){
 addTemporary=dlsym(RTLD_DEFAULT,"SCDynamicStoreAddTemporaryValue");setValue=dlsym(RTLD_DEFAULT,"SCDynamicStoreSetValue");removeValue=dlsym(RTLD_DEFAULT,"SCDynamicStoreRemoveValue");
 if(!createStore||!addTemporary||!setValue||!removeValue)return NO;
 controlStore=createStore(NULL,CFSTR("iOSHotspotNamed16Control"),NULL,NULL);
 return controlStore&&addTemporary(controlStore,(__bridge CFStringRef)IH16ControlKey,(__bridge CFDictionaryRef)controlValue(NO));
}
static BOOL setRadio(BOOL on){__block BOOL okay=NO;dispatch_sync(dispatch_get_main_queue(),^{NSError *error=nil;okay=[radio setHotspot:on error:&error];if(!okay)failure=error.localizedDescription;});return okay;}
static BOOL journal(void){return IHNativeWriteJSON(IHNativeJournalPath,@{@"backend":IH16Backend,@"pid":@(getpid()),@"parentPID":session[@"parentPID"],@"nonce":session[@"nonce"],@"baseline4":@(baseline4),@"baseline6":@(baseline6),@"bridge":bridgeName?:@"",@"ipv6Aliases":ipv6Aliases?:@[],@"moves":@[]});}
static void releaseHeldRA(void){
 NSDictionary *diagnostic=IHNativeReadJSON(IH16MisdState);if(![diagnostic[@"nonce"] isEqual:session[@"nonce"]])return;
 for(NSNumber *pid in diagnostic[@"heldRA"])if(IHNativeProcess(pid.intValue,"rtadvd"))kill(pid.intValue,SIGCONT);
}
static void cleanup(void){
 double deadline=IHMonotonicTime()+IHVPNCleanupTimeout;
 atomic_store(&controlActive,false);blockForwarding();publish(@"stopping",NO);
 // 先解除本会话的启动挂起，确保系统的SIGTERM清理可以执行。
 releaseHeldRA();
 setRadio(NO);
 BOOL aliasesRemoved=YES;
 for(NSDictionary *entry in ipv6Aliases)if(if_nametoindex([entry[@"interface"] UTF8String])==[entry[@"index"] unsignedIntValue]&&IH16HasIPv6Address(entry[@"interface"],entry[@"address"])){
  if(!IHNativeIfconfigUntil(@[entry[@"interface"],@"inet6",entry[@"address"],@"-alias"],deadline,NULL))aliasesRemoved=NO;
 }
 if(store&&setQueue)setQueue(store,NULL);
 if(readinessToken>=0){notify_cancel(readinessToken);readinessToken=-1;}
 if(routeSource)dispatch_source_cancel(routeSource);if(ownerTimer)dispatch_source_cancel(ownerTimer);
 dispatch_sync(watchQueue,^{});if(routeFD>=0){close(routeFD);routeFD=-1;}
 if(controlStore){if(removeValue)removeValue(controlStore,(__bridge CFStringRef)IH16ControlKey);CFRelease(controlStore);controlStore=NULL;}
 // USB网桥对象可能保留；以系统服务已关闭且无共享接口为清理完成条件。
 double settleDeadline=MIN(deadline,IHMonotonicTime()+3);
 while(IHMonotonicTime()<settleDeadline&&!IH16SharingStopped())usleep(100000);
 if(aliasesRemoved&&IH16SharingStopped()){IHNativeSetForwarding(AF_INET,baseline4);IHNativeSetForwarding(AF_INET6,baseline6);unlink(IHNativeJournalPath.fileSystemRepresentation);}
 else{failure=@"系统热点网桥未释放，已阻断转发并保留恢复日志。";blockForwarding();}
 publish(failure.length?@"failed":@"stopped",NO);
}
static void runSession(void){@autoreleasepool{
 baseline4=IHKernelForwarding(AF_INET);baseline6=IHKernelForwarding(AF_INET6);
 if(baseline4<0||baseline6<0||!journal()){failure=@"无法保存内核转发基线。";publish(@"failed",NO);CFRunLoopStop(CFRunLoopGetMain());return;}
 do{
  BOOL ipv6=IHNativeIPv6Enabled(session);
  if(ipv6){struct in6_addr address={0};arc4random_buf(address.s6_addr,8);address.s6_addr[0]=0xfd;char text[INET6_ADDRSTRLEN];inet_ntop(AF_INET6,&address,text,sizeof(text));prefix=[@(text) stringByAppendingString:@"/64"];
   NSString *wifi=prefix;address.s6_addr[7]^=1;inet_ntop(AF_INET6,&address,text,sizeof(text));NSString *usb=[@(text) stringByAppendingString:@"/64"];
   NSMutableDictionary *updated=[session mutableCopy];updated[@"prefix"]=prefix;updated[@"prefixes"]=@{@"wifi":wifi,@"usb":usb};session=updated;if(!IHNativeWriteJSON(IHNativeSessionPath,session)){failure=@"无法保存本轮IPv6前缀授权。";break;}}
  startedAt=NSDate.date;if(!watchVPN()||(ipv6&&!serveControl())){failure=@"具名VPN事件门控或本地只读控制服务不可用。";break;}
  NSDate *deadline=[NSDate dateWithTimeIntervalSinceNow:15];double readySince=0;
  blockForwarding();if(!publish(@"waitingVPN",NO)){failure=@"无法保存VPN等待状态。";break;}
  BOOL settled=NO;
  while(deadline.timeIntervalSinceNow>0&&!atomic_load(&ending)){
   if(IHVPNStartupSettled(&readySince,IHMonotonicTime(),validVPN())){settled=YES;break;}
   dispatch_semaphore_wait(readinessWake,dispatch_time(DISPATCH_TIME_NOW,100*NSEC_PER_MSEC));
  }
  if(!settled){failure=failure?:@"VPN服务配置未在启动期限内稳定，未开启热点。";break;}
  atomic_store(&controlActive,ipv6);if(!publish(@"startingRadio",YES)){failure=@"无法保存热点准备状态。";break;}
  // 客户端可能在显式开启前就请求了本轮共享；唯一nonce足以区分旧会话。
  NSTimeInterval requestTime=0;
  radioRequestedAt=monotonicTime();if(!setRadio(YES))break;radioReturnedAt=monotonicTime();
  BOOL configured=NO,upstreamRetried=NO;
  readySince=0;
  while(deadline.timeIntervalSinceNow>0&&!atomic_load(&ending)){
   NSDictionary *diagnostic=IHNativeReadJSON(IH16MisdState);
   if([diagnostic[@"nonce"] isEqual:session[@"nonce"]]&&[diagnostic[ipv6?@"nat66Committed":@"nat44Committed"] boolValue]&&(!ipv6||[diagnostic[@"raConfigurationReady"] boolValue])){
    bridgeNames=IH16SessionBridges(session);bridgeName=bridgeNames.firstObject;
    if(bridgeNames.count&&validVPN()){configured=YES;break;}
   }
   // VPN提供者可能因网络变化再次发布配置。来源模块拒绝了本轮请求时，
   // 等严格身份校验重新稳定，再关闭并重发；始终沿用本轮授权和启动期限。
   // 原生认证首次只把不可用状态转为关闭；收到同轮准备确认后再请求一次开启。
   // 原有NAT、网桥、RA和VPN身份校验全部保留，准备确认不能直接放行。
   if(IHVPNUpstreamRetryAllowed(diagnostic,session[@"nonce"],upstreamRetried)&&validVPN()){
    upstreamRetried=YES;startupRetries++;requestTime=NSDate.date.timeIntervalSince1970;
    if(!setRadio(YES))break;
   }
   BOOL ready=IHVPNStartupSettled(&readySince,IHMonotonicTime(),validVPN());
   if(ready&&IHVPNStartupRetryAllowed(IHNativeReadJSON(IHSourceHookPath),session[@"nonce"],requestTime,startupRetries)){
    startupRetries++;if(!setRadio(NO))break;readySince=0;settled=NO;
    while(deadline.timeIntervalSinceNow>0&&!atomic_load(&ending)){
     if(IHVPNStartupSettled(&readySince,IHMonotonicTime(),validVPN())){settled=YES;break;}
     dispatch_semaphore_wait(readinessWake,dispatch_time(DISPATCH_TIME_NOW,100*NSEC_PER_MSEC));
    }
    if(!settled)break;requestTime=NSDate.date.timeIntervalSince1970;
    if(!publish(@"startingRadio",YES)||!setRadio(YES))break;
   }
   dispatch_semaphore_wait(readinessWake,dispatch_time(DISPATCH_TIME_NOW,100*NSEC_PER_MSEC));
  }
  if(!configured||failure.length||!journal()){failure=failure?:(ipv6?@"系统未确认匹配本轮VPN的NAT66和热点网桥，未放行。":@"系统未确认匹配本轮VPN的NAT44和热点网桥，未放行。");break;}
  if(ipv6&&!ensureIPv6Gateways()){failure=@"无法安装本轮IPv6网关，未放行。";break;}
  // 网关别名安装会再次触发路由变化；在原启动期限内等门控通过，不能只试一次。
  __block BOOL opened=NO;
  while(!opened&&!atomic_load(&ending)&&deadline.timeIntervalSinceNow>0){
   dispatch_sync(watchQueue,^{
    if(validVPN()&&!IHNativeSetForwarding(AF_INET,1)&&!IHNativeSetForwarding(AF_INET6,ipv6?1:0)){atomic_store(&gateOpen,true);started=YES;readyAt=monotonicTime();opened=publish(@"running",YES);}
    if(!opened)blockForwarding();
   });
   if(!opened)dispatch_semaphore_wait(readinessWake,dispatch_time(DISPATCH_TIME_NOW,100*NSEC_PER_MSEC));
  }
  if(!opened){failure=@"VPN门控没有在启动期限内通过校验。";break;}
  if(ipv6)releaseHeldRA();
  dispatch_semaphore_wait(ended,DISPATCH_TIME_FOREVER);
 }while(NO);
 atomic_store(&ending,true);cleanup();CFRunLoopStop(CFRunLoopGetMain());
}}
int main(int argc,char **argv){@autoreleasepool{
 startupAt=monotonicTime();
 if(geteuid()||argc!=2)return 2;
 // close-on-exec启动可能关闭标准输出；先补齐，避免后续子进程管道重用1/2后被关闭。
 for(int fd=0;fd<3;fd++){if(fcntl(fd,F_GETFD)<0){int opened=open("/dev/null",fd==0?O_RDONLY:O_WRONLY);if(opened<0)return 5;if(opened!=fd){if(dup2(opened,fd)<0){close(opened);return 5;}close(opened);}}fcntl(fd,F_SETFD,0);}
 session=IHNativeReadJSON(IHNativeSessionPath);if(![session[@"backend"] isEqual:IH16Backend]||![session[@"nonce"] isEqual:@(argv[1])]||!IHNativeProcess([session[@"parentPID"] intValue],"ioshotspotd")||!ownerValid())return 3;ipv6Aliases=[NSMutableArray new];
 radio=[[IHNetwork alloc]initForHotspotControl];ended=dispatch_semaphore_create(0);readinessWake=dispatch_semaphore_create(0);watchQueue=dispatch_queue_create("com.newbie.ioshotspot.named16.watch",DISPATCH_QUEUE_SERIAL);
 signal(SIGPIPE,SIG_IGN);signal(SIGTERM,SIG_IGN);signal(SIGINT,SIG_IGN);
 termSource=dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL,SIGTERM,0,watchQueue);dispatch_source_set_event_handler(termSource,^{requestStop(nil);});dispatch_resume(termSource);
 intSource=dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL,SIGINT,0,watchQueue);dispatch_source_set_event_handler(intSource,^{requestStop(nil);});dispatch_resume(intSource);
 dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{runSession();});CFRunLoopRun();return failure.length?1:0;
}}
