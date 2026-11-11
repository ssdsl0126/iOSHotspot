#import <Foundation/Foundation.h>
#import "IHNetwork.h"
#import "IHStore.h"
#import "IHClients.h"
#import "IHNativeVPN.h"
#import "IHVPNConnector.h"
#import "../common/IHNamedVPN16.h"
#import "../common/IHProtocol.h"
#import "../common/IHUnixSocket.h"
#import "../common/IHKernelVPN.h"
#import "../common/IHKernelRoute.h"
#import "../common/IHSourceMode.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <notify.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>

#ifndef IH_BUILD_VERSION
#define IH_BUILD_VERSION "development"
#endif

#define dataDirectory IHDataDirectory
#define journalPath IHNetworkJournalPath
static NSString * const unsupportedSourceMessage=@"不支持该共享来源。";
static BOOL IHSupportedSource(NSString *source){return IHSourceModeSupported(source);}
static BOOL IHSameVPNTunnel(NSDictionary *first,NSDictionary *second){
 if(!first.count||!second.count)return NO;
 for(NSString *key in @[@"interface",@"interfaceIndex",@"serviceID"])if(![first[key] isEqual:second[key]])return NO;
 return YES;
}
static BOOL IHAutomaticCleanupError(NSString *message){return [message containsString:@"仍在关闭共享接口"]||[message containsString:@"等待旧共享接口释放"];}
@interface IHService:NSObject
@property(nonatomic,strong) IHNetwork *network;
@property(nonatomic,strong) IHStore *store;
@property(nonatomic,strong) IHClients *clients;
@property(nonatomic,strong) dispatch_source_t expiryTimer;
@property(nonatomic,strong) NSDate *expiryDeadline;
@property(nonatomic,strong) NSDate *expiryRetryAfter;
@property(nonatomic,copy) NSString *expiryError;
@property(nonatomic) NSUInteger expiryGeneration;
@property(nonatomic,strong) NSMutableDictionary *seenClientPackets;
@property(nonatomic,strong) NSDictionary *baseline;
@property(nonatomic,strong) NSDictionary *vpnBinding;
@property(nonatomic,strong) NSDate *vpnStartedAt;
@property(nonatomic,strong) NSDate *stopRequestedAt;
@property(nonatomic,strong) NSDictionary *previousCounters;
@property(nonatomic,strong) NSDate *sessionStart,*idleSince,*lastCheckpoint;
@property(nonatomic) uint64_t sessionRx,sessionTx;
@property(nonatomic,strong) dispatch_source_t timer,listener;
@property(nonatomic,copy) NSString *lastError,*measuredInterface;
@property(nonatomic) BOOL processing;
@property(nonatomic,strong) IHNativeVPN *nativeVPN;
@property(nonatomic,strong) IHVPNConnector *vpnConnector;
@property(nonatomic) int legacyStartToken;
@property(nonatomic,copy) NSString *automaticSource;
@property(nonatomic,strong) NSDictionary *automaticIdentity;
@property(nonatomic,strong) NSDictionary *automaticStartPending,*automaticCleanupFailure;
@property(nonatomic) BOOL automaticHotspotRequested,automaticStartFailed,automaticWasOn,automaticReconciling;
@property(nonatomic) BOOL automaticStopping,automaticStopBlocked;
@property(nonatomic) double automaticStopDeadline;
@property(nonatomic,strong) dispatch_source_t automaticStopTimer;
- (NSDictionary*)request:(NSDictionary*)request;
- (void)event;
- (BOOL)captureNetworkBaseline:(NSError**)error;
- (BOOL)syncNativeSourcePolicy:(NSError**)error;
- (NSDictionary*)currentKernelVPNBinding;
- (NSDictionary*)networkSnapshot;
- (NSString*)effectiveSource;
- (NSDictionary*)startSharing;
- (NSDictionary*)performStartSharing;
- (void)reconcileAutomaticSource;
- (void)cancelAutomaticStopTimer;
@end
@implementation IHService
- (NSDictionary*)currentKernelVPNBinding{return IHKernelVPNBinding();}
- (NSDictionary*)networkSnapshot {
 NSDictionary *raw=_network.snapshot;
 if(![[self effectiveSource] isEqual:@"vpn"]||![_store.config[@"enabled"] boolValue])return raw;
 // 旧客户端可能不发布接口数组；只聚合本轮原生门控已核实的实际网桥。
 NSDictionary *session=IH16ActiveSession(),*state=IHNativeReadJSON(IHNativeStatePath);
 if(!session||![state[@"phase"] isEqual:@"running"]||![state[@"gateOpen"] isEqual:@YES]||
    !IH16IdentityMatches(session[@"binding"])||!IH16RoutesMatch(session[@"binding"]))return raw;
 NSArray *bridges=IH16SessionBridges(session);
 if(!bridges.count||![[NSSet setWithArray:bridges] isEqual:[NSSet setWithArray:state[@"bridges"]?:@[]]])return raw;
 NSString *name=session[@"binding"][@"interface"];NSMutableDictionary *value=[raw mutableCopy];
 [value addEntriesFromDictionary:@{@"upstream":name,@"externalInterfaces":@[name],@"internalInterfaces":bridges,@"active":@YES}];return value;
}
- (instancetype)init {if((self=[super init])){
 _legacyStartToken=-1;_nativeVPN=[IHNativeVPN new];_vpnConnector=[IHVPNConnector new];_store=[[IHStore alloc]initWithDirectory:dataDirectory];_network=[IHNetwork new];_lastError=@"";
 _clients=[[IHClients alloc]initWithQueue:dispatch_get_main_queue()];_seenClientPackets=[NSMutableDictionary dictionary];
 NSData *saved=[NSData dataWithContentsOfFile:journalPath];if(saved){id v=[NSJSONSerialization JSONObjectWithData:saved options:0 error:nil];if([v isKindOfClass:NSDictionary.class])_baseline=v;else _lastError=@"恢复日志损坏，禁止启动新的网络修改。";}
 __weak IHService *weak=self;_network.changed=^{[weak event];};_clients.changed=^{[weak collectClients];[weak announce];};
 _nativeVPN.changed=^{[weak event];};
 // 保留系统设置启动旧客户端会话的能力，不涉及其他后端或回退。
 if(notify_register_dispatch(IH16StartNotification,&_legacyStartToken,dispatch_get_main_queue(),^(int token){IHService *strong=weak;if(strong&&[strong.store.config[@"enabled"] boolValue]&&[[strong effectiveSource] isEqual:@"vpn"]&&strong.vpnBinding.count&&!strong.nativeVPN.busy)[strong request:@{@"command":@"start"}];})!=NOTIFY_STATUS_OK)_legacyStartToken=-1;
 [self writeSharingRuntimeEnabled:NO error:nil];
 NSError *recoveryError=nil;if(![_nativeVPN recover:&recoveryError])_lastError=recoveryError.localizedDescription;
 // 服务重启后先恢复项目拥有的网络变化，再允许新会话，避免残留转发。
 if(_baseline){NSError *error=nil;if([_network restoreBaseline:_baseline error:&error]){[[NSFileManager defaultManager]removeItemAtPath:journalPath error:nil];_baseline=nil;}else _lastError=error.localizedDescription?:@"网络恢复未完成。";}
 // VPN会话在服务重启后要求重新启用，不自动复用上一次隧道授权。
 if([@[@"vpn",@"auto"] containsObject:_store.config[@"source"]]||!IHSupportedSource(_store.config[@"source"]))[_store updateConfig:@{@"enabled":@NO} error:nil];
 // 启用状态恢复后同步非VPN来源，系统设置开关也必须读取到当前选择。
 NSError *policyError=nil;if(![self syncNativeSourcePolicy:&policyError])_lastError=policyError.localizedDescription?:@"共享来源同步失败。";
 [_store expireAt:NSDate.date];[_store save];[self event];
 }return self;}
- (void)dealloc {[self cancelAutomaticStopTimer];if(_legacyStartToken>=0)notify_cancel(_legacyStartToken);}
- (void)scheduleExpiry {
 // 其他状态事件也可能已成功保存；清掉本清理任务的旧失败状态，避免阻止后续启动。
 if(_expiryRetryAfter&&!_store.lastError){if([_lastError isEqual:_expiryError])_lastError=@"";_expiryError=nil;_expiryRetryAfter=nil;}
 NSDate *now=NSDate.date,*deadline=[_store nextExpiryDateAfter:now];
 // 失败后使用固定的绝对重试时刻，状态事件不能反复把重试向后推迟。
 if(deadline&&_expiryRetryAfter&&[deadline compare:_expiryRetryAfter]==NSOrderedAscending)deadline=_expiryRetryAfter;
 if(_expiryTimer&&[_expiryDeadline isEqual:deadline])return;
 // 已到期的数据只排一个即时任务，避免重复状态事件取消后重新排队。
 if(_expiryTimer&&deadline&&[deadline compare:now]!=NSOrderedDescending&&[_expiryDeadline compare:now]!=NSOrderedDescending)return;
 if(_expiryTimer){dispatch_source_cancel(_expiryTimer);_expiryTimer=nil;}NSUInteger generation=++_expiryGeneration;_expiryDeadline=deadline;if(!deadline)return;
 _expiryTimer=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,dispatch_get_main_queue());
 NSTimeInterval absolute=deadline.timeIntervalSince1970;struct timespec wall={.tv_sec=(time_t)absolute,.tv_nsec=(long)((absolute-(time_t)absolute)*NSEC_PER_SEC)};
 dispatch_source_set_timer(_expiryTimer,dispatch_walltime(&wall,0),DISPATCH_TIME_FOREVER,0);
 __weak IHService *weak=self;dispatch_source_set_event_handler(_expiryTimer,^{IHService *strong=weak;if(!strong||strong.expiryGeneration!=generation)return;
 if(strong.expiryTimer){dispatch_source_cancel(strong.expiryTimer);strong.expiryTimer=nil;}strong.expiryDeadline=nil;
 [strong.store expireAt:NSDate.date];if(![strong.store save]){strong.expiryError=strong.store.lastError.localizedDescription?:@"保留期限清理无法保存。";strong.lastError=strong.expiryError;strong.expiryRetryAfter=[NSDate dateWithTimeIntervalSinceNow:60];}
 else{if([strong.lastError isEqual:strong.expiryError])strong.lastError=@"";strong.expiryError=nil;strong.expiryRetryAfter=nil;}
 [strong scheduleExpiry];});dispatch_resume(_expiryTimer);
}
- (void)collectClients {
 NSDate *now=NSDate.date;NSArray *observed=[_clients clientsAt:now];NSMutableSet *identities=[NSMutableSet set];
 for(NSDictionary *client in observed){NSString *identity=client[@"id"];NSNumber *last=client[@"lastPacket"];if(!identity||!last)continue;[identities addObject:identity];if([_seenClientPackets[identity] isEqual:last])continue;
 [_store observeClients:@[client] at:[NSDate dateWithTimeIntervalSince1970:last.doubleValue]];_seenClientPackets[identity]=last;}
 // IHClients淘汰30天旧记录时同步删除去重缓存中的身份，不额外保留历史标识。
 for(NSString *identity in _seenClientPackets.allKeys)if(![identities containsObject:identity])[_seenClientPackets removeObjectForKey:identity];
}
- (BOOL)writeSharingRuntimeEnabled:(BOOL)enabled error:(NSError**)error {
 NSString *source=[self effectiveSource];NSMutableDictionary *value=[@{@"version":@1,@"enabled":@(enabled),@"source":source,@"upstream":[source isEqual:@"wifi"]?@"en0":@"",@"vpnIPv6":_store.config[@"vpnIPv6"]?:@NO} mutableCopy];
 if([source isEqual:@"vpn"]&&enabled){value[@"kernelBackendVersion"]=@4;value[@"nativeSession"]=_nativeVPN.nonce;value[@"allowLegacyStart"]=@(_vpnBinding.count>0);value[@"vpnBinding"]=_vpnBinding?:@{};value[@"upstream"]=_vpnBinding[@"interface"]?:@"";value[@"daemonPID"]=@(getpid());}
 // 先以0600创建临时文件，再替换授权；替换后chmod会暴露短暂的0644窗口。
 if(IHNativeWriteJSON(IHSourceRuntimePath,value))return YES;
 if(error)*error=[NSError errorWithDomain:NSPOSIXErrorDomain code:errno?:EIO userInfo:@{NSLocalizedDescriptionKey:@"无法原子保存共享授权。"}];return NO;
}
- (BOOL)captureNetworkBaseline:(NSError**)error {
 if(_baseline)return YES;
 NSDictionary *baseline=[_network captureBaseline];NSData *data=[NSJSONSerialization dataWithJSONObject:baseline options:0 error:error];
 if(!data||![data writeToFile:journalPath options:NSDataWritingAtomic error:error])return NO;
 _baseline=baseline;
 if(chmod(journalPath.fileSystemRepresentation,0600)){if(error)*error=[NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];return NO;}return YES;
}
- (BOOL)syncNativeSourcePolicy:(NSError**)error {
 NSString *source=[self effectiveSource];
 if(!IHSupportedSource(source))return [self writeSharingRuntimeEnabled:NO error:error];
 BOOL enabled=[_store.config[@"enabled"] boolValue];
 // 系统设置能直接启动热点，因此必须在发布来源策略前持久化原始状态。
 if(enabled&&![self captureNetworkBaseline:error])return NO;
 return [self writeSharingRuntimeEnabled:enabled error:error];
}
- (NSString*)effectiveSource {
 NSString *mode=_store.config[@"source"]?:@"cellular";
 return [mode isEqual:@"auto"]?(_automaticSource?:IHResolvedSource(mode,[_network.snapshot[@"vpnConnected"] boolValue],[_network.snapshot[@"wifiConnected"] boolValue])):mode;
}
- (BOOL)currentVPNRoutesReady:(NSDictionary*)binding {
 BOOL ipv6=[_store.config[@"vpnIPv6"] boolValue];
 return (!ipv6||IH16IdentityMatches(binding))&&IHKernelRoutesMatch([binding[@"interfaceIndex"] unsignedIntValue],ipv6);
}
- (NSDictionary*)automaticDetection {
 NSDictionary *current=[self currentKernelVPNBinding],*binding=current;
 NSDictionary *previous=_automaticIdentity[@"binding"];
 // 主网络发布可能暂时落后于VPN连接；同一服务的旧绑定只用于保留选择。
 // 新会话仍必须取得当前有效绑定及路由，不能用旧绑定通过启动预检。
 if([_network.snapshot[@"connectedVPNServiceIDs"] containsObject:previous[@"serviceID"]?:@""]&&
    (!binding.count||([binding[@"serviceID"] isEqual:previous[@"serviceID"]]&&IH16IdentityMatches(previous))||
     (IHSameVPNTunnel(previous,current)&&![self currentVPNRoutesReady:current])))binding=previous;
 BOOL currentBinding=IHNativeBindingMatches(binding,current,[_store.config[@"vpnIPv6"] boolValue]);
 BOOL vpn=binding.count>0||[_network.snapshot[@"vpnConnected"] boolValue];
 NSString *source=IHResolvedSource(@"auto",vpn,[_network.snapshot[@"wifiConnected"] boolValue]);
 return @{@"source":source,@"binding":binding?:@{},@"vpnReady":@(currentBinding&&binding.count>0&&[self currentVPNRoutesReady:binding])};
}
- (void)blockAutomaticForwarding {
 IHNativeSetForwarding(AF_INET,0);IHNativeSetForwarding(AF_INET6,0);
}
- (void)cancelAutomaticStopTimer {
 if(_automaticStopTimer){dispatch_source_cancel(_automaticStopTimer);_automaticStopTimer=nil;}
 _automaticStopping=NO;
}
- (void)reconcileAutomaticSource {
 if(![_store.config[@"source"] isEqual:@"auto"]||_automaticReconciling)return;
 if(!_automaticStopBlocked){
  NSDictionary *identity=[self automaticDetection],*raw=_network.snapshot[@"sharing"];NSString *target=identity[@"source"];
  NSDictionary *pending=_automaticStartPending;
  if(pending){
   BOOL same=[pending[@"source"] isEqual:target];NSDictionary *current=[self currentKernelVPNBinding];
   if([target isEqual:@"vpn"]&&current.count&&[pending[@"binding"] count]&&!IHSameVPNTunnel(current,pending[@"binding"]))same=NO;
   BOOL ready=[target isEqual:@"vpn"]?_nativeVPN.running:([raw[@"State"] intValue]==1023&&[raw[@"UState"] intValue]==1023);
   BOOL failed=[target isEqual:@"vpn"]&&[@[@"failed",@"unsupported"] containsObject:_nativeVPN.state[@"phase"]?:@""];
   if(!same||ready||failed)_automaticStartPending=nil;
   else if(IHMonotonicTime()<[pending[@"deadline"] doubleValue])return;
   else{_automaticStartPending=nil;_automaticStartFailed=YES;_lastError=@"共享接口未在启动期限内就绪，请关闭热点后重试。";[self writeSharingRuntimeEnabled:NO error:nil];return;}
  }
  if(_automaticCleanupFailure&&[_automaticCleanupFailure isEqual:identity]&&!IHSharingIsStopped(raw))return;
  _automaticCleanupFailure=nil;
  if(IHSharingIsUnavailableEmpty(raw)&&!_nativeVPN.busy&&[_store.config[@"enabled"] boolValue]){
   if(_automaticSource&&![_automaticSource isEqual:target]){
    NSError *error=nil;[self blockAutomaticForwarding];if(_automaticStopping)[self cancelAutomaticStopTimer];
    if(![_nativeVPN stop:&error]){_automaticStartFailed=YES;_lastError=error.localizedDescription;return;}
    _automaticSource=target;_automaticIdentity=identity;_vpnBinding=[target isEqual:@"vpn"]?identity[@"binding"]:nil;_vpnStartedAt=nil;_automaticStartFailed=NO;
    if(![self syncNativeSourcePolicy:&error]){_automaticStartFailed=YES;_lastError=error.localizedDescription;return;}
   }
   if([raw[@"UState"] intValue]==1023)_automaticWasOn=NO;
   if(_automaticHotspotRequested&&IHAutomaticCleanupError(_lastError)){_automaticStartFailed=NO;_lastError=@"";[self syncNativeSourcePolicy:nil];}
  }
 }
 BOOL finishedAutomaticStop=NO;
 if(_automaticStopping){
  if(_nativeVPN.busy){
   if(IHMonotonicTime()>=_automaticStopDeadline){[self cancelAutomaticStopTimer];_automaticStopBlocked=YES;_automaticStartFailed=YES;_lastError=@"原生VPN后台未在期限内退出，已阻断转发，请关闭热点后重试。";[self writeSharingRuntimeEnabled:NO error:nil];}
   return;
  }
  [self cancelAutomaticStopTimer];finishedAutomaticStop=YES;
 }
 if(_automaticStopBlocked)return;
 NSDictionary *identity=[self automaticDetection];NSString *target=identity[@"source"];
 BOOL identityChanged=![_automaticIdentity isEqual:identity];
 BOOL bindingChanged=![_automaticIdentity[@"binding"] isEqual:identity[@"binding"]];
 BOOL sourceChanged=_automaticSource&&![_automaticSource isEqual:target];
 BOOL active=[_network.snapshot[@"hotspotOn"] boolValue];NSString *phase=_nativeVPN.state[@"phase"]?:@"idle";
 if(!finishedAutomaticStop&&[@[@"failed",@"unsupported"] containsObject:phase])_automaticStartFailed=YES;
 if(![_store.config[@"enabled"] boolValue]){_automaticSource=target;_automaticIdentity=identity;_automaticHotspotRequested=NO;_automaticWasOn=NO;return;}
 if(active)_automaticHotspotRequested=YES;
 // 系统设置手动关闭也应取消跟随；VPN失效造成的关闭保留本轮开启意图。
 if(!finishedAutomaticStop&&_automaticWasOn&&!active&&!sourceChanged&&!identityChanged&&[@[@"idle",@"running",@"stopped"] containsObject:phase])_automaticHotspotRequested=NO;
 // 路由暂时未就绪由后台门控处理，不反复销毁同一条VPN会话。
 BOOL rebuild=sourceChanged||(_automaticSource&&[_automaticSource isEqual:@"vpn"]&&bindingChanged&&(_nativeVPN.busy||_automaticHotspotRequested));
 _automaticReconciling=YES;
 if(rebuild){
  NSError *error=nil;
  if(active||_nativeVPN.busy)[self blockAutomaticForwarding];
  if(active)[self sample];
  if(_nativeVPN.busy){
   // 自动切换不能同步等待后台清理，否则会堵住4秒状态请求。
   if(![_nativeVPN requestStop:&error]){_automaticStartFailed=YES;_automaticStopBlocked=YES;_lastError=error.localizedDescription;[self writeSharingRuntimeEnabled:NO error:nil];}
   else{
    _automaticStopping=YES;_automaticStopDeadline=IHMonotonicTime()+IHVPNStopTimeout;
    _automaticStopTimer=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,dispatch_get_main_queue());
    dispatch_source_set_timer(_automaticStopTimer,dispatch_time(DISPATCH_TIME_NOW,100*NSEC_PER_MSEC),100*NSEC_PER_MSEC,10*NSEC_PER_MSEC);
    __weak IHService *weak=self;dispatch_source_set_event_handler(_automaticStopTimer,^{[weak event];});dispatch_resume(_automaticStopTimer);
   }
   _automaticReconciling=NO;return;
  }
  BOOL stopped=YES;
  if(_nativeVPN.busy||[_automaticSource isEqual:@"vpn"])stopped=[_nativeVPN stop:&error];
  if(stopped&&(active||!IHSharingIsStopped(_network.snapshot[@"sharing"])))stopped=[_network setHotspot:NO error:&error];
  [_network refresh];
  if(!stopped||!IHSharingIsStopped(_network.snapshot[@"sharing"])){_lastError=error.localizedDescription?:@"自动模式正在等待旧共享接口释放。";_automaticStartFailed=YES;_automaticCleanupFailure=identity;[self writeSharingRuntimeEnabled:NO error:nil];_automaticReconciling=NO;return;}
  _vpnBinding=nil;_vpnStartedAt=nil;active=NO;_automaticWasOn=NO;
 }
 if(sourceChanged||bindingChanged||finishedAutomaticStop)_automaticStartFailed=NO;
 _automaticSource=target;_automaticIdentity=identity;
 if(identityChanged){
  _vpnBinding=[target isEqual:@"vpn"]?identity[@"binding"]:nil;
  NSError *error=nil;if(![self syncNativeSourcePolicy:&error]){_lastError=error.localizedDescription?:@"自动来源同步失败。";_automaticStartFailed=YES;}
 }
 if(_automaticHotspotRequested&&!active&&!_nativeVPN.busy&&!_automaticStartFailed){
  if([target isEqual:@"vpn"]&&![identity[@"vpnReady"] boolValue])_lastError=@"正在等待当前VPN的地址、DNS和路由就绪。";
  else{
   NSDictionary *response=[self startSharing];
   if(![response[@"ok"] boolValue]){_lastError=response[@"error"]?:@"自动来源启动失败。";_automaticStartFailed=YES;}
  }
 }
 _automaticWasOn=[_network.snapshot[@"hotspotOn"] boolValue];_automaticReconciling=NO;
}

- (NSDictionary*)startSharing {
 BOOL automatic=[_store.config[@"source"] isEqual:@"auto"];NSString *tag=NSUUID.UUID.UUIDString;
 if(automatic)_automaticStartPending=@{@"tag":tag,@"source":[self effectiveSource],@"binding":_automaticIdentity[@"binding"]?:@{},@"deadline":@(IHMonotonicTime()+IHHotspotTransitionTimeout)};
 NSDictionary *reply=[self performStartSharing];
 if(automatic){
  NSDictionary *raw=_network.snapshot[@"sharing"];
  BOOL ready=[[self effectiveSource] isEqual:@"vpn"]?_nativeVPN.running:([raw[@"State"] intValue]==1023&&[raw[@"UState"] intValue]==1023);
  if(![reply[@"ok"] boolValue]||ready)_automaticStartPending=nil;
 }
 if(automatic){
  __weak IHService *weak=self;
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW,IHHotspotTransitionTimeout*NSEC_PER_SEC),dispatch_get_main_queue(),^{IHService *strong=weak;if([strong.automaticStartPending[@"tag"] isEqual:tag])[strong event];});
 }
 return reply;
}
- (NSDictionary*)performStartSharing {
 NSError *error=nil;
  if(!IHSupportedSource(_store.config[@"source"]))return [self failure:unsupportedSourceMessage];
  if(![_store.config[@"enabled"] boolValue])return [self failure:@"请先启用 iOSHotspot。"];
  if(_store.readOnly)return [self failure:_store.lastError.localizedDescription?:@"存储处于只读保护状态。"];
  NSString *source=[self effectiveSource];
  if([source isEqual:@"vpn"]){
   if(_nativeVPN.busy||_vpnConnector.busy)return [self status];
   _vpnBinding=[self currentKernelVPNBinding];if(!_vpnBinding.count){if(![_store.config[@"source"] isEqual:@"auto"]&&[_store.config[@"autoVPN"] boolValue])return [self beginAutomaticVPNStart];return [self failure:@"VPN 未连接或隧道/DNS 尚未就绪，未开启热点。"];}[_vpnConnector cancel];
   NSDictionary *hook=[self sourceHookState];
   if(![hook[@"build"] isEqual:@(IHSourcePolicyBuild)])return [self failure:@"新的具名来源模块尚未加载，未开启 VPN 热点。"];
   if(![_nativeVPN prepare:_vpnBinding ipv6:[_store.config[@"vpnIPv6"] boolValue] error:&error])return [self failure:error.localizedDescription];
  }
  if([source isEqual:@"wifi"]){
   // 上次VPN拒绝记录不代表Wi-Fi模块未加载，按实际Hook身份预检。
   if(![_nativeVPN.capabilities[@"wifiSourceHookReady"] boolValue])return [self failure:@"Wi-Fi 来源模块未在本机验证加载，未开启热点。"];
   if(![_nativeVPN.capabilities[@"wifiNativePrefixReady"] boolValue])return [self failure:@"Wi-Fi 原生前缀共享模块尚未就绪，未开启热点。"];
  }
  if(![self writeSharingRuntimeEnabled:YES error:&error])return [self failure:error.localizedDescription];
  if(![self captureNetworkBaseline:&error])return [self failure:error.localizedDescription];
  _lastError=@"";_stopRequestedAt=nil;if([source isEqual:@"vpn"])_vpnStartedAt=NSDate.date;
  BOOL started=[source isEqual:@"vpn"]?[_nativeVPN start:&error]:[_network setHotspot:YES error:&error];if(!started)return [self failure:error.localizedDescription];[self record:@"startRequested" details:@{@"source":source}];[self event];return [self status];
}

- (void)announce {notify_post("com.newbie.ioshotspot.changed");}
- (void)record:(NSString*)type details:(NSDictionary*)details {[_store appendEvent:type details:details at:NSDate.date];[_store save];[self scheduleExpiry];[self announce];}
- (NSString*)metricInterface {
 NSDictionary *counters=[_network interfaceCounters];
 // 仅在真实内侧热点接口计量。
 for(id item in [self networkSnapshot][@"internalInterfaces"]){NSString *name=nil;if([item isKindOfClass:NSString.class])name=item;else if([item isKindOfClass:NSDictionary.class])name=item[@"InterfaceName"]?:item[@"interfaceName"]?:item[@"Name"];if(name&&counters[name])return name;}
 return @"";
}
- (void)sample {
 NSString *name=[self metricInterface];NSDictionary *counters=[_network interfaceCounters];NSDictionary *current=counters[name];NSDate *now=NSDate.date;
 if(current&&[_measuredInterface isEqual:name]&&_previousCounters){uint64_t oldIn=[_previousCounters[@"rx"] unsignedLongLongValue],oldOut=[_previousCounters[@"tx"] unsignedLongLongValue];uint64_t in=[current[@"rx"] unsignedLongLongValue],out=[current[@"tx"] unsignedLongLongValue];
  // 若系统重建接口导致计数归零，重新建立基线，绝不产生巨大虚假差值。
  uint64_t upload=in>=oldIn?in-oldIn:0,download=out>=oldOut?out-oldOut:0;
  _sessionRx+=download;_sessionTx+=upload;[_store recordRx:download tx:upload at:now];
 }
 _previousCounters=current;_measuredInterface=name;
 if(!_lastCheckpoint||[now timeIntervalSinceDate:_lastCheckpoint]>=60){[_store save];_lastCheckpoint=now;}
}
- (void)event {
 if(_processing)return;_processing=YES;[_network refresh];[self reconcileAutomaticSource];
 if(_automaticStopping||_automaticStopBlocked){_processing=NO;[self announce];return;}
 BOOL active=[_network.snapshot[@"hotspotOn"] boolValue];BOOL enabled=[_store.config[@"enabled"] boolValue];
 if(enabled&&[[self effectiveSource] isEqual:@"vpn"]){
  NSDictionary *state=_nativeVPN.state;NSString *phase=state[@"phase"];
  if([@[@"creating",@"startingRadio",@"running",@"paused",@"stopping"] containsObject:phase]&&!_nativeVPN.busy){
   IHNativeSetForwarding(AF_INET,0);IHNativeSetForwarding(AF_INET6,0);_vpnBinding=nil;[self writeSharingRuntimeEnabled:YES error:nil];[_network setHotspot:NO error:nil];
   _lastError=@"原生 VPN 后台意外退出，已阻断转发并关闭热点。";
  }
  if(_nativeVPN.running&&!active){_vpnBinding=nil;[self writeSharingRuntimeEnabled:YES error:nil];[_nativeVPN stop:nil];}
  if([@[@"failed",@"unsupported"] containsObject:phase]){
   if([_store.config[@"source"] isEqual:@"auto"])_automaticStartFailed=YES;
   _lastError=state[@"error"]?:@"原生 VPN 会话失败，热点已关闭。";_vpnBinding=nil;[self writeSharingRuntimeEnabled:YES error:nil];
  }
  // 无线服务就绪前不开始统计和无客户端倒计时。
  active=_nativeVPN.running&&active;
 }
 NSDictionary *snapshot=[self networkSnapshot];NSArray *internal=snapshot[@"internalInterfaces"]?:@[];[_clients updateInterfaces:enabled?internal:@[] systemSnapshot:snapshot];[self collectClients];
 if(active&&enabled){
  if(!_sessionStart){_sessionStart=NSDate.date;_sessionRx=0;_sessionTx=0;_idleSince=NSDate.date;_previousCounters=nil;}
  [self sample];
  if(!_timer){_timer=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,dispatch_get_main_queue());dispatch_source_set_timer(_timer,dispatch_time(DISPATCH_TIME_NOW,5*NSEC_PER_SEC),5*NSEC_PER_SEC,NSEC_PER_SEC);__weak IHService *weak=self;dispatch_source_set_event_handler(_timer,^{[weak event];});dispatch_resume(_timer);}
  NSUInteger clients=[_network.snapshot[@"clientCount"] unsignedIntegerValue];if(clients)_idleSince=nil;else if(!_idleSince)_idleSince=NSDate.date;
  NSString *reason=nil;NSInteger idle=[_store.config[@"idleMinutes"] integerValue],batteryLimit=[_store.config[@"lowBatteryPercent"] integerValue];uint64_t dailyLimit=[_store.config[@"dailyLimitBytes"] unsignedLongLongValue];
  NSDictionary *totals=[_store totalsAt:NSDate.date];NSInteger battery=[_network batteryPercent];
  if(idle&&_idleSince&&[NSDate.date timeIntervalSinceDate:_idleSince]>=idle*60)reason=@"idle";
  if(batteryLimit&&battery>=0&&battery<=batteryLimit)reason=@"lowBattery";
  if(dailyLimit&&[totals[@"todayRx"] unsignedLongLongValue]+[totals[@"todayTx"] unsignedLongLongValue]>=dailyLimit)reason=@"dailyLimit";
  if([[self effectiveSource] isEqual:@"wifi"]&&[_network.snapshot[@"externalInterfaces"] count]&&![_network.snapshot[@"upstream"] isEqual:@"en0"])reason=@"selectedSourceUnavailable";
  if(reason){_automaticHotspotRequested=NO;_automaticWasOn=NO;NSError *error=nil;if([[self effectiveSource] isEqual:@"vpn"])[_nativeVPN stop:&error];else [_network setHotspot:NO error:&error];_lastError=error.localizedDescription?:@"";[self record:@"automaticStop" details:@{@"reason":reason}];}
 }else{
  _vpnStartedAt=nil;
  if(_timer){dispatch_source_cancel(_timer);_timer=nil;}
  if(_sessionStart){[_store save];_sessionStart=nil;_previousCounters=nil;_measuredInterface=@"";[self record:@"sessionEnded" details:@{}];}
 }
 if([_store.config[@"source"] isEqual:@"auto"])_automaticWasOn=[_network.snapshot[@"hotspotOn"] boolValue];
 [_store expireAt:NSDate.date];[self scheduleExpiry];_processing=NO;[self announce];
}
- (NSDictionary*)status {
 [_network refresh];NSMutableDictionary *result=[[self networkSnapshot] mutableCopy];[result removeObjectForKey:@"sharing"];
 result[@"ok"]=@YES;result[@"enabled"]=_store.config[@"enabled"];result[@"config"]=_store.config;result[@"source"]=_store.config[@"source"];result[@"effectiveSource"]=[self effectiveSource];
 result[@"automaticSource"]=@{@"active":@([_store.config[@"source"] isEqual:@"auto"]),@"requested":@(_automaticHotspotRequested),@"phase":_automaticStartFailed?@"failed":(_automaticReconciling||_automaticStopping)?@"switching":(_automaticHotspotRequested&&[[self effectiveSource] isEqual:@"vpn"]&&!_nativeVPN.running)?@"waitingVPN":@"idle"};
 [self collectClients];NSMutableArray *recent=[NSMutableArray array];NSArray *history=[_store historyAt:NSDate.date];NSDictionary *names=[NSDictionary dictionaryWithObjects:[history valueForKey:@"name"] forKeys:[history valueForKey:@"id"]];
 for(NSDictionary *client in [_clients clientsAt:NSDate.date])if([client[@"activeRecent"] boolValue]){NSMutableDictionary *value=[client mutableCopy];if(names[value[@"id"]])value[@"name"]=names[value[@"id"]];value[@"connected"]=@YES;[recent addObject:value];}
 result[@"clients"]=recent;result[@"clientDiscovery"]=_clients.diagnostics;result[@"history"]=history;
 result[@"sessionStarted"]=_sessionStart?@(_sessionStart.timeIntervalSince1970):@0;result[@"sessionRx"]=@(_sessionRx);result[@"sessionTx"]=@(_sessionTx);
 [result addEntriesFromDictionary:[_store totalsAt:NSDate.date]];
 result[@"lastError"]=_store.lastError.localizedDescription?:(_network.error.length?_network.error:_lastError);
 NSMutableDictionary *vpn=[_nativeVPN.state mutableCopy];vpn[@"supported"]=@(_nativeVPN.supported);vpn[@"phase"]=vpn[@"phase"]?:@"idle";vpn[@"backend"]=_nativeVPN.supported?IH16Backend:@"unavailable";vpn[@"capabilities"]=_nativeVPN.capabilities;vpn[@"binding"]=_vpnBinding?:@{};NSDictionary *pfDiagnostic=IHNativeReadJSON(IH16MisdState);vpn[@"ownPFRules"]=@([pfDiagnostic[@"nonce"] isEqual:(_nativeVPN.nonce?:@"")]&&[pfDiagnostic[@"legacyPrefixCompatibility"] boolValue]);vpn[@"customPFAnchor"]=@NO;vpn[@"privateOffsets"]=@NO;vpn[@"routeTo"]=@NO;vpn[@"userspacePacketRelay"]=@NO;vpn[@"validationScope"]=@"仅以项目记录中实际设备、系统版本与VPN配置的验收为准。";result[@"vpnSharing"]=vpn;
 result[@"version"]=@IH_BUILD_VERSION;result[@"osVersion"]=[NSProcessInfo processInfo].operatingSystemVersionString;
 result[@"vpnAutoConnect"]=_vpnConnector.state?:@{@"supported":@NO,@"busy":@NO,@"phase":@"idle",@"error":@""};
 result[@"batteryPercent"]=@([_network batteryPercent]);result[@"measuredInterface"]=_measuredInterface?:@"";result[@"statisticsScope"]=@"本月仅包含最近30天；上下行仅累计实际热点内侧接口，含网络协议开销。";
 result[@"capabilities"]=@{@"nativeBackend":@(_network.available),@"cellular":@(_network.available),@"auto":@YES,@"wifi":@YES,@"vpn":@(_nativeVPN.supported),@"clientIdentity":@YES,@"powerPollingWhileOff":@NO};
 return result;
}
- (NSDictionary*)failure:(NSString*)message {return @{@"ok":@NO,@"error":message?:@"未知错误"};}
- (NSDictionary*)sourceHookState {return IHNativeReadJSON(IHSourceHookPath);}
- (NSDictionary*)beginAutomaticVPNStart {
 if(_vpnConnector.busy)return [self status];
 if(!_vpnConnector.supported)return [self failure:@"系统VPN控制助手不可用，请手动连接VPN。"];
 NSDictionary *capabilities=_nativeVPN.capabilities;
 if(!_nativeVPN.supported||![capabilities[@"sourceHookReady"] boolValue]||![capabilities[@"legacyHooksReady"] boolValue])return [self failure:@"VPN共享模块尚未就绪，未自动连接VPN或开启热点。"];
 _lastError=@"";__weak IHService *weak=self;
 BOOL accepted=[_vpnConnector connectWithCompletion:^(NSDictionary *result){
  IHService *strong=weak;if(!strong||![strong.store.config[@"enabled"] boolValue]||![strong.store.config[@"autoVPN"] boolValue]||![strong.store.config[@"source"] isEqual:@"vpn"])return;
  if(![result[@"ok"] boolValue]){strong.lastError=result[@"error"]?:@"系统VPN连接失败，热点保持关闭。";[strong.vpnConnector recordFailure:strong.lastError];[strong announce];return;}
  NSDictionary *binding=[strong currentKernelVPNBinding];NSString *expected=result[@"selectedServiceID"],*actual=binding[@"serviceID"];
  if(![expected isKindOfClass:NSString.class]||![actual isKindOfClass:NSString.class]||[expected caseInsensitiveCompare:actual]!=NSOrderedSame){strong.lastError=@"系统主VPN与自动连接目标不一致，未开启热点。";[strong.vpnConnector recordFailure:strong.lastError];[strong announce];return;}
  // 回到同一开启流程，继续检查DNS、路由及原生共享能力，不跳过原有门控。
  NSDictionary *response=[strong request:@{@"command":@"start"}];if(![response[@"ok"] boolValue]){strong.lastError=response[@"error"]?:@"VPN已连接，但热点启动检查未通过。";[strong.vpnConnector recordFailure:strong.lastError];[strong announce];}
 }];
 if(!accepted)return [self failure:@"无法发起系统VPN连接，热点保持关闭。"];
 [self announce];return [self status];
}
- (NSDictionary*)request:(NSDictionary*)request {
 NSString *command=request[@"command"];NSError *error=nil;
 if([@[@"start",@"stop",@"disable",@"configure",@"toggle"] containsObject:command?:@""]){_automaticStartPending=nil;_automaticCleanupFailure=nil;}
 if([command isEqual:@"status"])return [self status];
 if([command isEqual:@"report"]){NSMutableDictionary *report=[[self status] mutableCopy];[report removeObjectsForKeys:@[@"password",@"ssid",@"clients",@"history"]];report[@"events"]=[_store eventsAt:NSDate.date];NSData *data=[NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:&error];return data?@{@"ok":@YES,@"report":[[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]}:[self failure:error.localizedDescription];}
 if([command isEqual:@"configure"]){if(![request[@"config"] isKindOfClass:NSDictionary.class])return [self failure:@"配置格式错误。"];
  if(request[@"config"][@"source"]&&!IHSupportedSource(request[@"config"][@"source"]))return [self failure:unsupportedSourceMessage];
  if(request[@"config"][@"enabled"])return [self failure:@"请使用启用或停用命令，以执行完整的网络回滚。"];
  BOOL sourceChanged=request[@"config"][@"source"]&&![_store.config[@"source"] isEqual:request[@"config"][@"source"]];
  for(NSString *key in @[@"autoVPN",@"vpnIPv6"])if(request[@"config"][key]&&![request[@"config"][key] isKindOfClass:NSNumber.class])return [self failure:@"VPN选项格式错误。"];
  BOOL modeChanged=request[@"config"][@"vpnIPv6"]&&[request[@"config"][@"vpnIPv6"] boolValue]!=[_store.config[@"vpnIPv6"] boolValue];
  if((sourceChanged||modeChanged)&&_vpnConnector.busy)return [self failure:@"正在等待VPN连接，请先关闭热点启动请求再更改来源或IPv6选项。"];
  if([request[@"config"][@"autoVPN"] boolValue]&&!_vpnConnector.supported)return [self failure:@"系统VPN控制助手不可用。"];
  // 外部开启VPN或系统热点时SC通知可能尚未处理，不能用上次缓存放行来源切换。
  if(sourceChanged||modeChanged)[_network refresh];
  BOOL sharingStopped=IHSharingIsStopped(_network.snapshot[@"sharing"]);
  if(sourceChanged&&(!sharingStopped||_nativeVPN.busy))return [self failure:@"请先关闭热点，等待共享接口清理完成后再更改来源。"];
  if(modeChanged&&(_nativeVPN.busy||(!sharingStopped&&[[self effectiveSource] isEqual:@"vpn"])))return [self failure:@"请先关闭VPN热点，再更改IPv6共享选项。"];
  NSDictionary *previous=[_store.config copy];
  if(request[@"config"][@"source"]&&![_store.config[@"source"] isEqual:request[@"config"][@"source"]])_vpnBinding=nil;
  if(![_store updateConfig:request[@"config"] error:&error])return [self failure:error.localizedDescription];
  if(sourceChanged){[self cancelAutomaticStopTimer];_automaticStopBlocked=NO;_automaticSource=nil;_automaticIdentity=nil;_automaticHotspotRequested=NO;_automaticStartFailed=NO;_automaticWasOn=NO;}
  if(request[@"config"][@"autoVPN"]&&![request[@"config"][@"autoVPN"] boolValue])[_vpnConnector cancel];
  if((request[@"config"][@"source"]||request[@"config"][@"vpnIPv6"])&&![self syncNativeSourcePolicy:&error]){[_store updateConfig:previous error:nil];[self syncNativeSourcePolicy:nil];return [self failure:error.localizedDescription];}
  [self event];return [self status];}
 if([command isEqual:@"rename"]){if(![_store renameClient:request[@"id"] name:request[@"name"] error:&error])return [self failure:error.localizedDescription];return [self status];}
 if([command isEqual:@"clear"]){if(_store.readOnly)return [self failure:_store.lastError.localizedDescription?:@"存储处于只读保护状态，无法清除。"];
  [_clients clearHistory];[_seenClientPackets removeAllObjects];[_store clear];[self scheduleExpiry];_sessionRx=0;_sessionTx=0;_previousCounters=nil;
  if(_store.lastError)return [self failure:_store.lastError.localizedDescription];return [self status];}
 if([command isEqual:@"enable"]){if(!IHSupportedSource(_store.config[@"source"]))return [self failure:unsupportedSourceMessage];
  if([_store.config[@"source"] isEqual:@"vpn"]){if(!_nativeVPN.supported)return [self failure:@"系统缺少具名原生网络 API；旧偏移后端已移除，VPN 共享不可用。"];
   _vpnBinding=[self currentKernelVPNBinding];if(!_vpnBinding.count&&(![_store.config[@"autoVPN"] boolValue]||!_vpnConnector.supported))return [self failure:@"未找到系统主隧道、实际地址与专属DNS一致的VPN，未启用共享。"];}BOOL wasEnabled=[_store.config[@"enabled"] boolValue];if(![_store updateConfig:@{@"enabled":@YES} error:&error])return [self failure:error.localizedDescription];
  if(![self syncNativeSourcePolicy:&error]){[_store updateConfig:@{@"enabled":@(wasEnabled)} error:nil];[self syncNativeSourcePolicy:nil];return [self failure:error.localizedDescription];}[self event];return [self status];}
 if([command isEqual:@"disable"]){
  _automaticHotspotRequested=NO;_automaticWasOn=NO;
  [_vpnConnector cancel];
  [self sample];
  if(_nativeVPN.busy||[[self effectiveSource] isEqual:@"vpn"]){if(![_nativeVPN stop:&error])return [self failure:error.localizedDescription];if(![_network setHotspot:NO error:&error])return [self failure:error.localizedDescription];_vpnBinding=nil;[self writeSharingRuntimeEnabled:YES error:nil];}
  if(![self writeSharingRuntimeEnabled:NO error:&error])return [self failure:error.localizedDescription];if(_baseline){if(![_network restoreBaseline:_baseline error:&error])return [self failure:error.localizedDescription];[[NSFileManager defaultManager]removeItemAtPath:journalPath error:nil];_baseline=nil;}
  if(![_store updateConfig:@{@"enabled":@NO} error:&error])return [self failure:error.localizedDescription];[self cancelAutomaticStopTimer];_automaticStopBlocked=NO;[self event];[self record:@"disabled" details:@{}];return [self status];}
 if([command isEqual:@"toggle"]){[_network refresh];command=[_network.snapshot[@"hotspotOn"] boolValue]?@"stop":@"start";}
 if([command isEqual:@"start"]){
  if([_store.config[@"source"] isEqual:@"auto"]){
   if(![_store.config[@"enabled"] boolValue])return [self failure:@"请先启用 iOSHotspot。"];
   if(_automaticStopBlocked)return [self failure:_lastError?:@"请先关闭热点，完成旧会话清理后再开启。"];
   if(!_nativeVPN.busy&&[@[@"failed",@"unsupported"] containsObject:_nativeVPN.state[@"phase"]?:@""]&&![_nativeVPN stop:&error])return [self failure:error.localizedDescription];
   _automaticHotspotRequested=YES;_automaticStartFailed=NO;[self event];
   return _automaticStartFailed?[self failure:_lastError]:[self status];
  }return [self startSharing];}
 if([command isEqual:@"stop"]){
  _automaticHotspotRequested=NO;_automaticWasOn=NO;
  [_vpnConnector cancel];
  if(_automaticStopping)return [self status];
  [self sample];_stopRequestedAt=NSDate.date;BOOL vpn=_nativeVPN.busy||[[self effectiveSource] isEqual:@"vpn"];
  if(vpn&&![_nativeVPN stop:&error]){_stopRequestedAt=nil;return [self failure:error.localizedDescription];}
  // 即使配置为VPN却没有存活的宿主，也必须实际关闭系统热点。
  if(![_network setHotspot:NO error:&error]){_stopRequestedAt=nil;return [self failure:error.localizedDescription];}
  if(vpn){_vpnBinding=nil;[self writeSharingRuntimeEnabled:YES error:nil];}
  _automaticStopBlocked=NO;[self record:@"stopRequested" details:@{}];[self event];return [self status];}
 return [self failure:@"不支持的命令。"];
}
@end

static IHService *service;
static void handleClient(int fd){@autoreleasepool{
 uid_t uid;gid_t gid;if(getpeereid(fd,&uid,&gid)!=0||(uid!=0&&uid!=501)){close(fd);return;}
 int flags=fcntl(fd,F_GETFL,0);if(flags<0||fcntl(fd,F_SETFL,flags&~O_NONBLOCK)<0){close(fd);return;}
 struct timeval timeout={3,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
 NSMutableData *data=[NSMutableData data];char buf[4096];ssize_t n;
 while((n=read(fd,buf,sizeof(buf)))>0){[data appendBytes:buf length:n];if(data.length>16384)break;if(memchr(buf,'\n',n))break;}
 NSDictionary *response;NSError *error=nil;id request=data.length<=16384?[NSJSONSerialization JSONObjectWithData:data options:0 error:&error]:nil;
 if([request isKindOfClass:NSDictionary.class]){__block NSDictionary *value;dispatch_sync(dispatch_get_main_queue(),^{value=[service request:request];});response=value;}
 else response=@{@"ok":@NO,@"error":@"请求格式无效。"};
 NSData *output=[NSJSONSerialization dataWithJSONObject:response options:0 error:nil];size_t pos=0;while(pos<output.length){ssize_t wrote=write(fd,(char*)output.bytes+pos,output.length-pos);if(wrote<=0)break;pos+=wrote;}close(fd);
}}
int main(int argc,char **argv){@autoreleasepool{
 signal(SIGPIPE,SIG_IGN);
 if(argc>1){NSError *error=nil;NSMutableDictionary *request=[@{@"command":@(argv[1])} mutableCopy];if(argc>2){id args=[NSJSONSerialization JSONObjectWithData:[@(argv[2]) dataUsingEncoding:NSUTF8StringEncoding] options:0 error:&error];if([args isKindOfClass:NSDictionary.class])[request addEntriesFromDictionary:args];else{fprintf(stderr,"invalid JSON\n");return 2;}}
 NSDictionary *response=IHRequest(request,&error);if(!response){fprintf(stderr,"%s\n",error.localizedDescription.UTF8String);return 1;}NSData *data=[NSJSONSerialization dataWithJSONObject:response options:NSJSONWritingPrettyPrinted error:nil];fwrite(data.bytes,1,data.length,stdout);fputc('\n',stdout);return [response[@"ok"] boolValue]?0:2;}
 service=[IHService new];int fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0)return 1;
 fcntl(fd,F_SETFD,FD_CLOEXEC);
 unlink(IHSocketPath.fileSystemRepresentation);
 if(IHUnixSocketOperation(fd,IHSocketPath,YES)<0||listen(fd,8)<0)return 2;chown(IHSocketPath.fileSystemRepresentation,0,501);chmod(IHSocketPath.fileSystemRepresentation,0660);fcntl(fd,F_SETFL,O_NONBLOCK);
 dispatch_source_t listener=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,fd,0,dispatch_get_main_queue());service.listener=listener;
 dispatch_source_set_event_handler(listener,^{int client;while((client=accept(fd,NULL,NULL))>=0){fcntl(client,F_SETFD,FD_CLOEXEC);dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{handleClient(client);});}});dispatch_resume(listener);
 signal(SIGTERM,SIG_IGN);signal(SIGINT,SIG_IGN);for(int signum=SIGTERM;signum<=SIGTERM;signum++){dispatch_source_t sig=dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL,signum,0,dispatch_get_main_queue());dispatch_source_set_event_handler(sig,^{[service.nativeVPN stop:nil];[service.store save];exit(0);});dispatch_resume(sig);}
 CFRunLoopRun();return 0;
}}
