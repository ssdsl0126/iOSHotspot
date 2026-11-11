#import "IHNativeVPN.h"
#import "../common/IHNativeVPNProtocol.h"
#import "../common/IHNamedVPN16.h"
#include <notify.h>

@implementation IHNativeVPN{
 BOOL _supported;pid_t _pid;NSString *_nonce;int _token;BOOL _registered;dispatch_source_t _exitWatch;
}
- (instancetype)init{if((self=[super init])){_token=-1;__weak IHNativeVPN *weak=self;
 // 仅检查具名能力，不按系统版本分流，也不试开热点。
 void *net=dlopen("/System/Library/PrivateFrameworks/Netrb.framework/Netrb",RTLD_NOW);
 _supported=net&&dlsym(net,"_NETRBClientCreate")&&dlsym(net,"_NETRBClientDestroy")&&dlsym(net,"_NETRBClientSetGlobalServiceState")&&dlsym(net,"_NETRBClientGetGlobalServiceState");
 _registered=notify_register_dispatch(IHNativeNotification,&_token,dispatch_get_main_queue(),^(int token){if(weak.changed)weak.changed();})==NOTIFY_STATUS_OK;
 }return self;}
- (void)dealloc{if(_registered)notify_cancel(_token);}
- (BOOL)supported{return _supported;}
- (NSDictionary*)capabilities{
 NSDictionary *misd=IHNativeReadJSON(IH16MisdState),*source=IHNativeReadJSON(IHSourceHookPath),*usb=IHNativeReadJSON(IHUSBSourceHookPath);
 BOOL wifiReady=[source[@"build"] isEqual:@(IHSourcePolicyBuild)]&&[source[@"hookInstalled"] boolValue]&&IHNativeProcess([source[@"pid"] intValue],"wifid");
 BOOL usbReady=[usb[@"build"] isEqual:@(IHSourcePolicyBuild)]&&[usb[@"hookInstalled"] boolValue]&&IHNativeProcess([usb[@"pid"] intValue],"UserEventAgent");
 BOOL sourceReady=wifiReady&&usbReady;
 BOOL current=[misd[@"sourcePolicyBuild"] isEqual:@(IHSourcePolicyBuild)]&&IHNativeProcess([misd[@"pid"] intValue],"misd");
 BOOL legacy=sourceReady&&current&&_supported&&[misd[@"legacyHooksReady"] boolValue];
 BOOL family=sourceReady&&current&&[misd[@"familyGuardReady"] boolValue];
 BOOL wifiPrefix=current&&[misd[@"wifiPrefixReady"] boolValue];
 return @{@"legacyClientAPI":@(_supported),@"legacyHooksReady":@(legacy),@"sourceHookReady":@(sourceReady),@"wifiSourceHookReady":@(wifiReady),@"wifiNativePrefixReady":@(wifiPrefix),@"usbSourceHookReady":@(usbReady),@"familyGuardReady":@(family),@"plannedIPv4Backend":legacy?IH16Backend:@"unavailable",@"plannedIPv6Backend":legacy?IH16Backend:@"unavailable",@"selectionTiming":@"beforeHotspotStart",@"usesOSVersion":@NO};
}
- (NSString*)nonce{return _nonce?:@"";}
- (NSDictionary*)state{NSDictionary *state=IHNativeReadJSON(IHNativeStatePath);if(!_nonce.length||![state[@"nonce"] isEqual:_nonce])return @{};return state?:@{};}
- (BOOL)busy{return _pid>1&&IHNativeProcess(_pid,IH16Helper.UTF8String);}
- (BOOL)running{return self.busy&&[self.state[@"phase"] isEqual:@"running"];}
- (BOOL)fail:(NSString*)message error:(NSError**)error{if(error)*error=[NSError errorWithDomain:@"iOSHotspot.NativeVPN" code:1 userInfo:@{NSLocalizedDescriptionKey:message}];return NO;}
- (BOOL)recover:(NSError**)error{
 return [self recoverUntil:IHMonotonicTime()+IHVPNStopTimeout error:error];
}
- (BOOL)recoverUntil:(double)deadline error:(NSError**)error{
 NSDictionary *journal=IHNativeReadJSON(IHNativeJournalPath);if(!journal)return YES;
 IHNativeSetForwarding(AF_INET,0);IHNativeSetForwarding(AF_INET6,0);
 if(![journal[@"backend"] isEqual:IH16Backend])return [self fail:@"发现无法识别的旧恢复日志，禁止继续启动共享。" error:error];
 const char *helper=IH16Helper.UTF8String;
 pid_t pid=[journal[@"pid"] intValue];if(IHNativeProcess(pid,helper)){kill(pid,SIGTERM);while(IHMonotonicTime()<deadline&&IHNativeProcess(pid,helper))usleep(100000);if(IHNativeProcess(pid,helper))return [self fail:@"前一次原生 VPN 会话仍在退出，禁止叠加新会话。" error:error];}
 if(!IHNativeReadJSON(IHNativeJournalPath))return YES;
 for(NSDictionary *entry in journal[@"ipv6Aliases"]){NSString *name=entry[@"interface"],*address=entry[@"address"];if(IHNativeInterfaceName(name)&&if_nametoindex(name.UTF8String)==[entry[@"index"] unsignedIntValue]&&IH16HasIPv6Address(name,address)&&!IHNativeIfconfigUntil(@[name,@"inet6",address,@"-alias"],deadline,error))return NO;}
 NSString *bridge=journal[@"bridge"];if(IHNativeInterfaceName(bridge)&&if_nametoindex(bridge.UTF8String)&&!IH16SharingStopped())return [self fail:@"前一次原生网桥仍未释放，已阻断转发；保留恢复日志。" error:error];
 int first=[journal[@"baseline4"] intValue],second=[journal[@"baseline6"] intValue];
 if((first!=0&&first!=1)||(second!=0&&second!=1))return [self fail:@"原生会话恢复日志无效。" error:error];
 if(IHNativeSetForwarding(AF_INET,first)||IHNativeSetForwarding(AF_INET6,second))return [self fail:@"内核转发基线恢复失败。" error:error];
 unlink(IHNativeJournalPath.fileSystemRepresentation);return YES;
}
- (BOOL)prepare:(NSDictionary*)binding ipv6:(BOOL)ipv6 error:(NSError**)error{
 if(!_supported)return [self fail:@"当前系统没有可用的具名 VPN 共享接口。" error:error];
 if(self.busy)return [self fail:@"原生 VPN 会话仍在运行，请先停止。" error:error];
 if(![self recover:error])return NO;
 if(!IHNativeBindingMatches(binding,IHKernelVPNBinding(),ipv6))return [self fail:@"VPN 隧道、地址或 DNS 尚未就绪。" error:error];
 if(ipv6&&!IH16IdentityMatches(binding))return [self fail:@"VPN服务地址与DNS仍在更新，请稍后开启热点。" error:error];
 NSDictionary *capabilities=self.capabilities;
 if(![capabilities[@"sourceHookReady"] boolValue])return [self fail:@"具名来源模块尚未就绪，未开启热点。" error:error];
 if(!ipv6&&![capabilities[@"familyGuardReady"] boolValue])return [self fail:@"IPv4单栈保护模块尚未加载，请在热点关闭后重新加载系统共享服务。" error:error];
 if(![capabilities[@"legacyHooksReady"] boolValue])return [self fail:@"所需具名接口或保护模块不可用，启动前检查未通过。" error:error];
 if(!IHKernelRoutesMatch([binding[@"interfaceIndex"] unsignedIntValue],ipv6)||(ipv6&&![binding[@"ipv6addresses"] count]))return [self fail:ipv6?@"VPN的IPv6地址或路由未就绪；请在VPN中开启IPv6，或关闭“VPN IPv6共享”。":@"VPN的IPv4路由尚未就绪。" error:error];

 _nonce=NSUUID.UUID.UUIDString;
 NSMutableDictionary *session=[@{@"version":@1,@"nonce":_nonce,@"parentPID":@(getpid()),@"binding":binding,@"entities":IHNativeEntitiesForMode(binding,ipv6),@"vpnIPv6":@(ipv6),@"backend":IH16Backend} mutableCopy];
 NSDictionary *subnets=IH16AllocateSubnets();if(!subnets)return [self fail:@"没有找到两个不与现有接口重叠的共享网段，未开启热点。" error:error];session[@"ipv4Subnets"]=subnets;
 if(!IHNativeBindingValid(session)||!IHNativeWriteJSON(IHNativeSessionPath,session))return [self fail:@"无法保存有效的 VPN 会话授权。" error:error];
 return YES;
}
- (BOOL)start:(NSError**)error{
 if(!_supported)return [self fail:@"具名 VPN 共享接口不可用。" error:error];
 if(self.busy)return YES;
 if(!_nonce.length)return [self fail:@"原生 VPN 会话尚未授权。" error:error];
 NSString *helperPath=IHJailbreakPath(@"/usr/libexec/ioshotspot-vpn16");const char *path=helperPath.fileSystemRepresentation;char *arguments[]={(char*)path,(char*)_nonce.UTF8String,NULL};
 // 后台不能继承命令连接，否则客户端一直等不到 EOF。
 posix_spawnattr_t attributes;posix_spawnattr_init(&attributes);posix_spawnattr_setflags(&attributes,POSIX_SPAWN_CLOEXEC_DEFAULT);
 int code=posix_spawn(&_pid,path,NULL,&attributes,arguments,environ);posix_spawnattr_destroy(&attributes);if(code){_pid=0;return [self fail:[NSString stringWithFormat:@"无法启动原生 VPN 后台（%d）。",code] error:error];}
 pid_t launched=_pid;_exitWatch=dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC,_pid,DISPATCH_PROC_EXIT,dispatch_get_main_queue());
 __weak IHNativeVPN *weak=self;dispatch_source_set_event_handler(_exitWatch,^{IHNativeVPN *strong=weak;if(!strong)return;int status=0;waitpid(launched,&status,WNOHANG);
  if(strong->_pid==launched){
   strong->_pid=0;
   // 先清理旧监听，再通知服务；回调可能立即启动下一轮，不能取消新监听。
   if(strong->_exitWatch){dispatch_source_cancel(strong->_exitWatch);strong->_exitWatch=nil;}
   IHNativeSetForwarding(AF_INET,0);IHNativeSetForwarding(AF_INET6,0);if(strong.changed)strong.changed();
  }
 });dispatch_resume(_exitWatch);return YES;
}
- (BOOL)requestStop:(NSError**)error{
 if(!self.busy)return YES;
 if(kill(_pid,SIGTERM)==0||errno==ESRCH)return YES;
 return [self fail:@"无法请求原生VPN后台退出，已保留原会话。" error:error];
}
- (BOOL)stop:(NSError**)error{
 double deadline=IHMonotonicTime()+IHVPNStopTimeout;
 const char *helper=IH16Helper.UTF8String;
 if(_pid>1&&IHNativeProcess(_pid,helper)){kill(_pid,SIGTERM);int status=0;BOOL finished=NO;
  do{pid_t result=waitpid(_pid,&status,WNOHANG);if(result==_pid||(result<0&&errno==ECHILD&&!IHNativeProcess(_pid,helper))){finished=YES;break;}usleep(100000);}while(IHMonotonicTime()<deadline);
  if(!finished){IHNativeSetForwarding(AF_INET,0);IHNativeSetForwarding(AF_INET6,0);return [self fail:@"原生 VPN 后台未完成退出，已阻断转发并保留恢复日志。" error:error];}
 }
 if(_exitWatch){dispatch_source_cancel(_exitWatch);_exitWatch=nil;}
 _pid=0;_nonce=nil;unlink(IHNativeSessionPath.fileSystemRepresentation);return [self recoverUntil:deadline error:error];
}
@end
