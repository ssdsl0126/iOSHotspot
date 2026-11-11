#import "../common/IHNamedVPN16.h"
#import "WiFiPrefix.h"
#include <xpc/xpc.h>
#include <sys/ioctl.h>
#include <notify.h>
#include <objc/runtime.h>
#include <objc/message.h>

static SCDynamicStoreRef (*originalCreate)(CFAllocatorRef,CFStringRef,SCDynamicStoreCallBack,SCDynamicStoreContext*);
static Boolean (*originalKeys)(SCDynamicStoreRef,CFArrayRef,CFArrayRef);
static CFPropertyListRef (*originalCopy)(SCDynamicStoreRef,CFStringRef);
static int (*originalSysctl)(int*,u_int,void*,size_t*,void*,size_t);
static int (*originalByName)(const char*,void*,size_t*,void*,size_t);
static int (*originalSpawn)(pid_t*,const char*,const posix_spawn_file_actions_t*,const posix_spawnattr_t*,char*const*,char*const*);
static Boolean (*originalAddRule)(void*,uintptr_t,xpc_object_t);
// PF旧接口四个参数全部透传，第三参数及完成回调不能丢失。
static Boolean (*originalCommit)(void*,uintptr_t,uintptr_t,void*);
static Boolean (*notifyValue)(SCDynamicStoreRef,CFStringRef);
static NSMutableDictionary *callbacks,*ruleSessions,*diagnostic;
static NSMutableSet *deferred;
static BOOL ready,familyGuardReady;
// 参数仅按Objective-C方法传递；不解引用系统私有结构。
static void (*originalConvertStatus)(id,SEL,void*,id);
static NSMutableSet *preparedUpstreams;
static BOOL vpnUpstreamReady;
static void updateDiagnostic(NSDictionary *session,NSDictionary *values);

static NSString *ruleKey(void *user,uintptr_t transaction){return [NSString stringWithFormat:@"%p:%llu",user,(unsigned long long)transaction];}
static void recordRule(NSDictionary *session,void *user,uintptr_t transaction,NSDictionary *values){
 @synchronized(ruleSessions){NSString *key=ruleKey(user,transaction);NSMutableDictionary *entry=[ruleSessions[key] mutableCopy]?:[NSMutableDictionary new];if(![entry[@"nonce"] isEqual:session[@"nonce"]])[entry removeAllObjects];entry[@"nonce"]=session[@"nonce"];[entry addEntriesFromDictionary:values];ruleSessions[key]=entry;}
}
static BOOL prefixPassRule(xpc_object_t rule,NSDictionary *session){
 // 前缀共享分支生成的精确形状；旧系统的原生NAT66规则不匹配此条件。
 if(!session||!IHNativeIPv6Enabled(session)||xpc_dictionary_get_uint64(rule,"family")!=AF_INET6||xpc_dictionary_get_uint64(rule,"action")!=0||xpc_dictionary_get_uint64(rule,"direction")!=1||xpc_dictionary_get_uint64(rule,"state")!=1)return NO;
 if(xpc_dictionary_get_uint64(rule,"rtableid")!=[session[@"binding"][@"interfaceIndex"] unsignedIntValue])return NO;
 const char *internal=xpc_dictionary_get_string(rule,"interface");if(!internal||!IH16BridgeTransport(session,@(internal)))return NO;
 xpc_object_t from=xpc_dictionary_get_value(rule,"from"),to=xpc_dictionary_get_value(rule,"to");
 if(!from||!to||xpc_get_type(from)!=XPC_TYPE_DICTIONARY||xpc_get_type(to)!=XPC_TYPE_DICTIONARY)return NO;
 const char *address=xpc_dictionary_get_string(from,"address-number"),*any=xpc_dictionary_get_string(to,"address-label");
 NSArray *parts=address?[@(address) componentsSeparatedByString:@"/"]:nil;struct in6_addr prefix={0};
 return any&&!strcmp(any,"any")&&parts.count==2&&[parts[1] isEqual:@"64"]&&inet_pton(AF_INET6,[parts[0] UTF8String],&prefix)==1&&!IN6_IS_ADDR_LINKLOCAL(&prefix);
}
static BOOL prefixBlockRule(xpc_object_t rule,NSDictionary *session){
 if(!session||!IHNativeIPv6Enabled(session)||xpc_dictionary_get_uint64(rule,"family")!=AF_INET6||xpc_dictionary_get_uint64(rule,"action")!=1||xpc_dictionary_get_uint64(rule,"direction")!=1)return NO;
 const char *internal=xpc_dictionary_get_string(rule,"interface");NSString *transport=internal?IH16BridgeTransport(session,@(internal)):nil;
 return transport!=nil;
}
static BOOL addCompatiblePass(void *user,uintptr_t transaction,NSDictionary *session,NSString *bridge,NSString *prefix){
 xpc_object_t rule=xpc_dictionary_create(NULL,NULL,0),from=xpc_dictionary_create(NULL,NULL,0),to=xpc_dictionary_create(NULL,NULL,0);if(!rule||!from||!to)return NO;
 xpc_dictionary_set_uint64(rule,"action",0);xpc_dictionary_set_uint64(rule,"direction",1);xpc_dictionary_set_uint64(rule,"family",AF_INET6);xpc_dictionary_set_uint64(rule,"state",1);
 xpc_dictionary_set_uint64(rule,"rtableid",[session[@"binding"][@"interfaceIndex"] unsignedIntValue]);xpc_dictionary_set_string(rule,"interface",bridge.UTF8String);
 xpc_dictionary_set_string(from,"address-number",prefix.UTF8String);xpc_dictionary_set_string(to,"address-label","any");xpc_dictionary_set_value(rule,"from",from);xpc_dictionary_set_value(rule,"to",to);
 return originalAddRule(user,transaction,rule);
}
static BOOL addCompatibleNAT66(void *user,uintptr_t transaction,NSDictionary *session,NSString *prefix){
 // 沿用系统旧PF事务及原生NAT字典，不创建额外anchor、不改misd内存或私有对象。
 NSString *upstream=session[@"binding"][@"interface"];NSArray *parts=[prefix componentsSeparatedByString:@"/"];struct in6_addr address={0};
 if(parts.count!=2||![parts[1] isEqual:@"64"]||inet_pton(AF_INET6,[parts[0] UTF8String],&address)!=1||address.s6_addr[0]!=0xfd)return NO;
 xpc_object_t rule=xpc_dictionary_create(NULL,NULL,0),from=xpc_dictionary_create(NULL,NULL,0),nat=xpc_dictionary_create(NULL,NULL,0);
 if(!rule||!from||!nat)return NO;
 xpc_dictionary_set_uint64(rule,"action",4);xpc_dictionary_set_string(rule,"interface",upstream.UTF8String);xpc_dictionary_set_uint64(rule,"family",AF_INET6);
 xpc_dictionary_set_uint64(rule,"extfilter",3);xpc_dictionary_set_uint64(rule,"extmap",3);
 xpc_dictionary_set_string(from,"address-number",prefix.UTF8String);xpc_dictionary_set_value(rule,"from",from);
 xpc_dictionary_set_string(nat,"address-dyninterface",[[upstream stringByAppendingString:@":0"] UTF8String]);
 xpc_dictionary_set_uint64(nat,"address-lowPort",0x8000);xpc_dictionary_set_uint64(nat,"address-highPort",0xbfff);xpc_dictionary_set_uint64(nat,"address-portOperator",0);
 xpc_dictionary_set_value(rule,"nat-rdr-address",nat);return originalAddRule(user,transaction,rule);
}

// Apple XNU公开in6_ifreq ABI；不对应misd对象或任何固件偏移。
struct IH16AddressRequest{char name[IFNAMSIZ];union{struct sockaddr_in6 address;int flags;unsigned char statistics[272];}value;};
_Static_assert(sizeof(struct IH16AddressRequest)==288,"Darwin in6_ifreq ABI不符");
static CFDictionaryRef copyRealIPv6(NSString *name){
 struct ifaddrs *head=NULL;if(getifaddrs(&head))return NULL;int fd=socket(AF_INET6,SOCK_DGRAM,0);if(fd<0){freeifaddrs(head);return NULL;}
 NSMutableArray *addresses=[NSMutableArray new],*flags=[NSMutableArray new],*prefixes=[NSMutableArray new];
 for(struct ifaddrs *p=head;p;p=p->ifa_next){
  if(!p->ifa_addr||strcmp(p->ifa_name,name.UTF8String)||p->ifa_addr->sa_family!=AF_INET6)continue;
  struct sockaddr_in6 *address=(void*)p->ifa_addr;if(IN6_IS_ADDR_UNSPECIFIED(&address->sin6_addr)||IN6_IS_ADDR_LOOPBACK(&address->sin6_addr)||IN6_IS_ADDR_MULTICAST(&address->sin6_addr))continue;
  struct IH16AddressRequest request={0};strlcpy(request.name,name.UTF8String,sizeof(request.name));request.value.address=*address;
  if(ioctl(fd,_IOWR('i',73,struct IH16AddressRequest),&request))continue;
  char text[INET6_ADDRSTRLEN];if(!inet_ntop(AF_INET6,&address->sin6_addr,text,sizeof(text)))continue;
  int prefix=0;if(p->ifa_netmask){const uint8_t *bytes=((struct sockaddr_in6*)p->ifa_netmask)->sin6_addr.s6_addr;for(int i=0;i<16;i++)for(int bit=7;bit>=0;bit--)if(bytes[i]&(1<<bit))prefix++;}
  [addresses addObject:@(text)];[flags addObject:@(request.value.flags)];[prefixes addObject:@(prefix)];
 }close(fd);freeifaddrs(head);if(!addresses.count)return NULL;
 return CFBridgingRetain(@{@"Addresses":addresses,@"Flags":flags,@"PrefixLength":prefixes});
}
static void updateDiagnostic(NSDictionary *session,NSDictionary *values){
 @synchronized(diagnostic){
  if(session&&[diagnostic[@"nonce"] isEqual:session[@"nonce"]]){BOOL changed=NO;for(NSString *key in values)if(![diagnostic[key] isEqual:values[key]]){changed=YES;break;}if(!changed)return;}
  if(session&&![(diagnostic[@"nonce"]?:@"") isEqual:session[@"nonce"]]){[diagnostic removeAllObjects];diagnostic[@"nonce"]=session[@"nonce"];diagnostic[@"heldRA"]=@[];}
  [diagnostic addEntriesFromDictionary:values];diagnostic[@"build"]=IH16Backend;diagnostic[@"packageVersion"]=@(IH_BUILD_VERSION);diagnostic[@"sourcePolicyBuild"]=@(IHSourcePolicyBuild);diagnostic[@"ready"]=@(ready);diagnostic[@"legacyHooksReady"]=@(ready);diagnostic[@"familyGuardReady"]=@(familyGuardReady);diagnostic[@"vpnUpstreamReady"]=@(vpnUpstreamReady);diagnostic[@"wifiPrefixReady"]=@(IHWiFiPrefixIsReady());diagnostic[@"vpnIPv6PolicyVersion"]=@1;diagnostic[@"pid"]=@(getpid());diagnostic[@"time"]=@(NSDate.date.timeIntervalSince1970);if(IHNativeWriteRuntimeJSON(IH16MisdState,diagnostic))notify_post(IH16ReadyNotification);
 }
}
// VPN上游不依赖蜂窝认证；只在本轮授权、隧道地址/DNS及路由全部匹配时适配。
static void convertVPNStatus(id object,SEL selector,void *status,id rawStatus){
 NSDictionary *session=IHNativeFamilyPolicySession();
 BOOL active=status&&rawStatus&&IHNativeProcess([session[@"parentPID"] intValue],"ioshotspotd")&&IH16IdentityMatches(session[@"binding"])&&IH16RoutesMatch(session[@"binding"]);
 if(!active){originalConvertStatus(object,selector,status,rawStatus);return;}
 // 只改传给系统转换方法的副本，属性读写全部经过具名方法。
 id copy=[rawStatus copy],availability=[NSClassFromString(@"CTDataConnectionAvailabilityStatus") new],connection=[NSClassFromString(@"CTDataConnectionStatus") new];
 ((void(*)(id,SEL,id))objc_msgSend)(copy,sel_registerName("setCarrierEnabled:"),@YES);
 ((void(*)(id,SEL,id))objc_msgSend)(copy,sel_registerName("setUserAuthenticated:"),@YES);
 ((void(*)(id,SEL,BOOL))objc_msgSend)(availability,sel_registerName("setAvailable:"),YES);
 ((void(*)(id,SEL,id))objc_msgSend)(copy,sel_registerName("setConnectionAvailabilityStatus:"),availability);
 ((void(*)(id,SEL,int))objc_msgSend)(connection,sel_registerName("setState:"),2);
 ((void(*)(id,SEL,id))objc_msgSend)(connection,sel_registerName("setPdp:"),@(-1));
 ((void(*)(id,SEL,id))objc_msgSend)(connection,sel_registerName("setInterfaceName:"),session[@"binding"][@"interface"]);
 ((void(*)(id,SEL,id))objc_msgSend)(copy,sel_registerName("setConnectionStatus:"),connection);
 originalConvertStatus(object,selector,status,copy);
 NSString *nonce=session[@"nonce"];@synchronized(preparedUpstreams){if([preparedUpstreams containsObject:nonce])return;[preparedUpstreams removeAllObjects];[preparedUpstreams addObject:nonce];}
 // 回到当前系统队列更新misd的共享快照；不调用蜂窝激活，不修改CoreTelephony状态。
 dispatch_async(dispatch_get_current_queue(),^{@autoreleasepool{
  NSDictionary *current=IHNativeFamilyPolicySession();
  if(![current[@"nonce"] isEqual:nonce]||!IH16IdentityMatches(current[@"binding"])||!IH16RoutesMatch(current[@"binding"]))return;
  ((void(*)(id,SEL,id))objc_msgSend)(object,sel_registerName("processCTTetheringStatusChangeNotification:"),rawStatus);
  updateDiagnostic(current,@{@"vpnUpstreamPrepared":@YES});
 }});
}
static BOOL installVPNUpstream(void){
 Class cls=objc_getClass("misCTClientSharedInstance");SEL convert=sel_registerName("convertTetheringStatus:CTStatus:"),event=sel_registerName("processCTTetheringStatusChangeNotification:");
 Method method=cls?class_getInstanceMethod(cls,convert):NULL;void(*hook)(Class,SEL,IMP,IMP*)=dlsym(RTLD_DEFAULT,"MSHookMessageEx");
 if(!method||!class_getInstanceMethod(cls,event)||method_getNumberOfArguments(method)!=4||!hook||!dlsym(RTLD_DEFAULT,"dispatch_get_current_queue"))return NO;
 char *result=method_copyReturnType(method),*output=method_copyArgumentType(method,2),*input=method_copyArgumentType(method,3);
 BOOL valid=result&&*result=='v'&&output&&*output=='^'&&input&&*input=='@';free(result);free(output);free(input);if(!valid)return NO;
 NSDictionary *requirements=@{@"CTTetheringStatus":@[@"copyWithZone:",@"setCarrierEnabled:",@"setUserAuthenticated:",@"setConnectionAvailabilityStatus:",@"setConnectionStatus:"],@"CTDataConnectionAvailabilityStatus":@[@"setAvailable:"],@"CTDataConnectionStatus":@[@"setState:",@"setPdp:",@"setInterfaceName:"]};
 for(NSString *name in requirements){Class target=NSClassFromString(name);for(NSString *methodName in requirements[name])if(!target||!class_getInstanceMethod(target,NSSelectorFromString(methodName)))return NO;}
 preparedUpstreams=[NSMutableSet new];hook(cls,convert,(IMP)convertVPNStatus,(IMP*)&originalConvertStatus);return originalConvertStatus!=NULL;
}
static NSString *interfaceKey(NSDictionary *s,NSString *family){return [NSString stringWithFormat:@"State:/Network/Interface/%@/%@",s[@"binding"][@"interface"],family];}
static void storeChanged(SCDynamicStoreRef store,CFArrayRef changes,void *context){@autoreleasepool{
 SCDynamicStoreCallBack callback=NULL;@synchronized(callbacks){callback=(SCDynamicStoreCallBack)[callbacks[[NSString stringWithFormat:@"%p",store]] pointerValue];}if(!callback)return;
 NSDictionary *session=IH16ActiveSession();NSArray *keys=(__bridge NSArray*)changes;if(!session||!IHNativeIPv6Enabled(session)||![keys isKindOfClass:NSArray.class]){callback(store,changes,context);return;}
 NSString *key4=interfaceKey(session,@"IPv4"),*key6=interfaceKey(session,@"IPv6");if(![keys containsObject:key4]&&![keys containsObject:key6]){callback(store,changes,context);return;}
 NSMutableArray *replacement=[keys mutableCopy];NSString *nonce=session[@"nonce"];BOOL first=NO;
 @synchronized(deferred){first=![deferred containsObject:nonce];if(first)[deferred addObject:nonce];}
 if(first){
  [replacement removeObject:key6];CFRetain(store);
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW,500*NSEC_PER_MSEC),dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{
   NSDictionary *current=IH16ActiveSession();if([current[@"nonce"] isEqual:nonce]&&notifyValue)notifyValue(store,(__bridge CFStringRef)key6);CFRelease(store);
  });
 }else if(![replacement containsObject:key6])[replacement addObject:key6];
 callback(store,(__bridge CFArrayRef)replacement,context);
}}
static SCDynamicStoreRef createStore(CFAllocatorRef allocator,CFStringRef name,SCDynamicStoreCallBack callback,SCDynamicStoreContext *context){
 BOOL ours=callback&&name&&CFEqual(name,CFSTR("com.apple.MobileInternetSharing"));
 SCDynamicStoreRef store=originalCreate(allocator,name,ours?storeChanged:callback,context);
 if(store&&ours)@synchronized(callbacks){callbacks[[NSString stringWithFormat:@"%p",store]]=[NSValue valueWithPointer:callback];}
 return store;
}
static Boolean notificationKeys(SCDynamicStoreRef store,CFArrayRef raw,CFArrayRef patterns){@autoreleasepool{
 NSDictionary *session=IH16ActiveSession();NSArray *keys=(__bridge NSArray*)raw;
 if(session&&IHNativeIPv6Enabled(session)&&[keys isKindOfClass:NSArray.class]&&[keys containsObject:interfaceKey(session,@"IPv4")]&&![keys containsObject:interfaceKey(session,@"IPv6")]){
  NSMutableArray *copy=[keys mutableCopy];[copy addObject:interfaceKey(session,@"IPv6")];return originalKeys(store,(__bridge CFArrayRef)copy,patterns);
 }return originalKeys(store,raw,patterns);
}}
static CFPropertyListRef copyValue(SCDynamicStoreRef store,CFStringRef key){@autoreleasepool{
 NSDictionary *session=IH16ActiveSession();if(session&&IHNativeIPv6Enabled(session)&&[(__bridge NSString*)key isEqual:interfaceKey(session,@"IPv6")]){
  CFDictionaryRef actual=copyRealIPv6(session[@"binding"][@"interface"]);if(actual)return actual;
 }return originalCopy(store,key);
}}
static int forwardingSysctl(int *name,u_int count,void *old,size_t *oldSize,void *value,size_t size){
 if(count==4&&value&&size==sizeof(int)&&*(int*)value==1&&name[0]==CTL_NET&&name[3]==1&&((name[1]==AF_INET&&name[2]==0)||(name[1]==AF_INET6&&name[2]==41))){
  NSDictionary *policy=IHNativeFamilyPolicySession();if(name[1]==AF_INET6&&policy&&!IHNativeIPv6Enabled(policy)){int zero=0;return originalSysctl(name,count,old,oldSize,&zero,sizeof(zero));}
  NSDictionary *session=IH16ActiveSession();NSDictionary *state=session?IHNativeReadJSON(IHNativeStatePath):nil;if(session&&![state[@"gateOpen"] boolValue]){int zero=0;return originalSysctl(name,count,old,oldSize,&zero,sizeof(zero));}
 }size_t capacity=oldSize?*oldSize:0;int result=originalSysctl(name,count,old,oldSize,value,size);
 if(!result&&!value)IHWiFiPrefixFilter(name,count,old,oldSize,capacity);return result;
}
static int forwardingByName(const char *name,void *old,size_t *oldSize,void *value,size_t size){
 if(name&&!strcmp(name,"net.inet6.ip6.forwarding")&&value&&size==sizeof(int)&&*(int*)value==1){NSDictionary *session=IHNativeFamilyPolicySession();if(session&&!IHNativeIPv6Enabled(session)){int zero=0;return originalByName(name,old,oldSize,&zero,sizeof(zero));}}
 return originalByName(name,old,oldSize,value,size);
}
static BOOL adaptRAConfiguration(NSDictionary *session,BOOL *adapted){
 *adapted=NO;NSString *path=@"/Library/Preferences/SystemConfiguration/com.apple.mis.rtadvd.conf";
 int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return NO;struct stat st;
 if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||st.st_size<1||st.st_size>32768){close(fd);return NO;}
 NSMutableData *data=[NSMutableData dataWithLength:(NSUInteger)st.st_size];size_t offset=0;
 while(offset<data.length){ssize_t n=read(fd,(char*)data.mutableBytes+offset,data.length-offset);if(n<0&&errno==EINTR)continue;if(n<=0){close(fd);return NO;}offset+=(size_t)n;}close(fd);
 NSString *text=[[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];if(!text)return NO;
 NSMutableArray *lines=[[text componentsSeparatedByString:@"\n"] mutableCopy];NSString *prefix=nil;
 for(NSUInteger i=0;i<lines.count;i++){
  NSString *line=lines[i];if(line.length&&![line hasPrefix:@"\t"]&&![line hasPrefix:@" "]){
   NSRange colon=[line rangeOfString:@":"];NSString *name=colon.location==NSNotFound?nil:[line substringToIndex:colon.location];prefix=name&&IHNativeInterfaceName(name)?IH16BridgePrefix(session,name):nil;if(prefix)*adapted=YES;
  }
  if(!prefix||![line hasPrefix:@"\t"])continue;
  NSString *address=[[prefix componentsSeparatedByString:@"/"] firstObject];
  NSArray *patterns=@[@"(?<=:)rltime#[0-9]+",@"(?<=:)addr0=\"[^\"]*\"",@"(?<=:)prefixlen0#[0-9]+",@"(?<=:)vltime0#[0-9]+",@"(?<=:)pltime0#[0-9]+",@"(?<=:)vltimedecr0#(?:true|false)",@"(?<=:)pltimedecr0#(?:true|false)"];
  NSArray *values=@[@"rltime#1800",[NSString stringWithFormat:@"addr0=\"%@\"",address],@"prefixlen0#64",@"vltime0#7200",@"pltime0#3600",@"vltimedecr0#false",@"pltimedecr0#false"];
  for(NSUInteger j=0;j<patterns.count;j++)line=[line stringByReplacingOccurrencesOfString:patterns[j] withString:values[j] options:NSRegularExpressionSearch range:NSMakeRange(0,line.length)];
  lines[i]=line;
 }
 if(!*adapted)return YES;NSData *output=[[lines componentsJoinedByString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];if(!output||output.length>32768)return NO;
 NSString *temporary=[path stringByAppendingFormat:@".ioshotspot-%d-%@",getpid(),NSUUID.UUID.UUIDString];fd=open(temporary.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)return NO;
 offset=0;BOOL okay=YES;while(offset<output.length){ssize_t n=write(fd,(const char*)output.bytes+offset,output.length-offset);if(n<0&&errno==EINTR)continue;if(n<=0){okay=NO;break;}offset+=(size_t)n;}
 if(fchown(fd,st.st_uid,st.st_gid)||fchmod(fd,st.st_mode&0777)||fsync(fd))okay=NO;close(fd);
 if(okay&&rename(temporary.fileSystemRepresentation,path.fileSystemRepresentation)==0)return YES;unlink(temporary.fileSystemRepresentation);return NO;
}
static int spawnProcess(pid_t *pid,const char *path,const posix_spawn_file_actions_t *actions,const posix_spawnattr_t *attributes,char *const *argv,char *const *environment){@autoreleasepool{
 if(path&&!strcmp(path,"/usr/sbin/rtadvd")&&!IHWiFiPrefixPrepareRA())return EINVAL;
 NSDictionary *session=path&&!strcmp(path,"/usr/sbin/rtadvd")?IH16ActiveSession():nil;
 if(!session||!IHNativeIPv6Enabled(session))return originalSpawn(pid,path,actions,attributes,argv,environment);
 BOOL adapted=NO;if(!adaptRAConfiguration(session,&adapted)){updateDiagnostic(session,@{@"raConfigurationReady":@NO,@"raConfigurationError":@"无法适配本轮IPv6通告配置"});return EINVAL;}
 if(!adapted)return originalSpawn(pid,path,actions,attributes,argv,environment);
 if([IHNativeReadJSON(IHNativeStatePath)[@"gateOpen"] boolValue]){int code=originalSpawn(pid,path,actions,attributes,argv,environment);updateDiagnostic(session,@{@"raConfigurationReady":@(code==0)});return code;}
 posix_spawnattr_t own;BOOL owned=!attributes;if(owned&&posix_spawnattr_init(&own))return EINVAL;
 posix_spawnattr_t *working=owned?&own:(posix_spawnattr_t*)attributes;short flags=0;int code=posix_spawnattr_getflags(working,&flags);
 if(!code)code=posix_spawnattr_setflags(working,flags|POSIX_SPAWN_START_SUSPENDED);
 if(!code){code=originalSpawn(pid,path,actions,working,argv,environment);posix_spawnattr_setflags(working,flags);}
 if(owned)posix_spawnattr_destroy(&own);
 if(!code&&pid){@synchronized(diagnostic){NSMutableArray *pids=[([diagnostic[@"nonce"] isEqual:session[@"nonce"]]?(diagnostic[@"heldRA"]?:@[]):@[]) mutableCopy];[pids addObject:@(*pid)];updateDiagnostic(session,@{@"heldRA":pids,@"raConfigurationReady":@YES});}}
 return code;
}}
static Boolean addRule(void *user,uintptr_t position,xpc_object_t rule){
 @autoreleasepool{NSDictionary *session=IH16ActiveSession();
 if(rule&&xpc_get_type(rule)==XPC_TYPE_DICTIONARY&&(prefixBlockRule(rule,session)||prefixPassRule(rule,session))){
  BOOL block=prefixBlockRule(rule,session);NSString *internal=@(xpc_dictionary_get_string(rule,"interface")),*prefix=IH16BridgePrefix(session,internal);if(!prefix.length)return false;
  if(block)updateDiagnostic(session,@{@"lastIPv6BlockInterface":internal,@"lastIPv6BlockTransport":IH16BridgeTransport(session,internal)?:@""});
  xpc_object_t copy=xpc_copy(rule);if(!block){xpc_object_t from=xpc_dictionary_create(NULL,NULL,0);xpc_dictionary_set_string(from,"address-number",prefix.UTF8String);xpc_dictionary_set_value(copy,"from",from);}
  Boolean accepted=originalAddRule(user,position,copy);if(!accepted)return accepted;
  NSString *key=ruleKey(user,position);NSArray *staged;@synchronized(ruleSessions){staged=ruleSessions[key][@"compatBridges"]?:@[];}
  if(![staged containsObject:internal]){
   if((block&&!addCompatiblePass(user,position,session,internal,prefix))||!addCompatibleNAT66(user,position,session,prefix))return false;
   recordRule(session,user,position,@{@"nat66":@YES,@"prefixCompatibility":@YES,@"compatBridges":[staged arrayByAddingObject:internal]});
  }return accepted;
 }
 Boolean accepted=originalAddRule(user,position,rule);if(!accepted||!rule||xpc_get_type(rule)!=XPC_TYPE_DICTIONARY||!session)return accepted;
  xpc_object_t from=xpc_dictionary_get_value(rule,"from");const char *source=from?xpc_dictionary_get_string(from,"address-number"):NULL,*interface=xpc_dictionary_get_string(rule,"interface");
  uint64_t family=xpc_dictionary_get_uint64(rule,"family");
  BOOL match=xpc_dictionary_get_uint64(rule,"action")==4&&interface&&[@(interface) isEqual:session[@"binding"][@"interface"]]&&(family==AF_INET||(family==AF_INET6&&source&&([(session[@"prefixes"]?:@{}) allValues]&&[[(session[@"prefixes"]?:@{}) allValues] containsObject:@(source)])));
  if(match)recordRule(session,user,position,@{(family==AF_INET?@"nat44":@"nat66"):@YES});
  return accepted;
 }
}
static Boolean commitRules(void *user,uintptr_t transaction,uintptr_t flags,void *completion){
 Boolean accepted=originalCommit(user,transaction,flags,completion);
 @autoreleasepool{NSDictionary *session=IH16ActiveSession(),*entry;@synchronized(ruleSessions){NSString *key=ruleKey(user,transaction);entry=ruleSessions[key];[ruleSessions removeObjectForKey:key];}
  if(accepted&&session&&[entry[@"nonce"] isEqual:session[@"nonce"]]){NSMutableDictionary *values=[NSMutableDictionary new];if([entry[@"nat44"] boolValue])values[@"nat44Committed"]=@YES;if([entry[@"nat66"] boolValue])values[@"nat66Committed"]=@YES;if([entry[@"prefixCompatibility"] boolValue])values[@"legacyPrefixCompatibility"]=@YES;updateDiagnostic(session,values);}
 }return accepted;
}
__attribute__((constructor))static void install(void){@autoreleasepool{
 if(strcmp(NSProcessInfo.processInfo.processName.UTF8String,"misd"))return;
 callbacks=[NSMutableDictionary new];ruleSessions=[NSMutableDictionary new];diagnostic=[NSMutableDictionary new];deferred=[NSMutableSet new];
 void(*hook)(void*,void*,void**)=dlsym(RTLD_DEFAULT,"MSHookFunction");if(!hook){void *library=dlopen(IHJailbreakPath(@"/usr/lib/libsubstrate.dylib").fileSystemRepresentation,RTLD_NOW);if(library)hook=dlsym(library,"MSHookFunction");}
 struct{const char *name;void *replacement;void **original;} entries[]={
  {"SCDynamicStoreCreate",createStore,(void**)&originalCreate},{"SCDynamicStoreSetNotificationKeys",notificationKeys,(void**)&originalKeys},{"SCDynamicStoreCopyValue",copyValue,(void**)&originalCopy},
  {"sysctl",forwardingSysctl,(void**)&originalSysctl},{"sysctlbyname",forwardingByName,(void**)&originalByName},{"posix_spawn",spawnProcess,(void**)&originalSpawn},{"PFUserAddRule",addRule,(void**)&originalAddRule},{"PFUserCommitRules",commitRules,(void**)&originalCommit}};
 notifyValue=dlsym(RTLD_DEFAULT,"SCDynamicStoreNotifyValue");ready=hook&&notifyValue;
 familyGuardReady=hook&&dlsym(RTLD_DEFAULT,"sysctl")&&dlsym(RTLD_DEFAULT,"sysctlbyname");
 NSMutableArray *missing=[NSMutableArray new];if(!hook)[missing addObject:@"MSHookFunction"];if(!notifyValue)[missing addObject:@"SCDynamicStoreNotifyValue"];
 for(size_t i=0;i<sizeof(entries)/sizeof(entries[0]);i++)if(!dlsym(RTLD_DEFAULT,entries[i].name)){ready=NO;[missing addObject:@(entries[i].name)];}
 // 分别核对转发保护与旧客户端扩展，缺少必要能力时拒绝启动。
 if(familyGuardReady)for(size_t i=0;i<sizeof(entries)/sizeof(entries[0]);i++)if(!strcmp(entries[i].name,"sysctl")||!strcmp(entries[i].name,"sysctlbyname")){hook(dlsym(RTLD_DEFAULT,entries[i].name),entries[i].replacement,entries[i].original);if(!*entries[i].original)familyGuardReady=NO;}
 ready=ready&&familyGuardReady;
 if(ready)for(size_t i=0;i<sizeof(entries)/sizeof(entries[0]);i++)if(strcmp(entries[i].name,"sysctl")&&strcmp(entries[i].name,"sysctlbyname")){hook(dlsym(RTLD_DEFAULT,entries[i].name),entries[i].replacement,entries[i].original);if(!*entries[i].original)ready=NO;}
 if(ready){IHWiFiPrefixInstall();vpnUpstreamReady=installVPNUpstream();}
 updateDiagnostic(nil,@{@"missingLegacySymbols":missing});
}}
