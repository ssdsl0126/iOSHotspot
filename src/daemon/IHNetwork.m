#import "IHNetwork.h"
#import "../common/IHTimeouts.h"
#import "../common/IHSharingState.h"
#import "../common/IHKernelVPN.h"
#import <SystemConfiguration/SystemConfiguration.h>
#include <dlfcn.h>
#include <dispatch/dispatch.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <notify.h>
#include <sys/sysctl.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

static CFPropertyListRef (*copyValue)(SCDynamicStoreRef,CFStringRef);
static CFDictionaryRef (*copyMultiple)(SCDynamicStoreRef,CFArrayRef,CFArrayRef);
static CFStringRef (*copyName)(SCDynamicStoreRef,CFStringEncoding *);
static CFTypeRef (*copyDeviceAnswer)(CFStringRef);
static SCDynamicStoreRef (*createStore)(CFAllocatorRef,CFStringRef,SCDynamicStoreCallBack,SCDynamicStoreContext *);
static Boolean (*setKeys)(SCDynamicStoreRef,CFArrayRef,CFArrayRef);
static Boolean (*setQueue)(SCDynamicStoreRef,dispatch_queue_t);
// 新旧实现均显式传零扩展参数，避免新版旧入口读取未初始化的第三寄存器。
static void *(*netCreate)(dispatch_queue_t,id,uintptr_t);
static void (*netDestroy)(void *);
static Boolean (*netSet)(void *,int);
static Boolean (*netGet)(void *,int*,int*);
static CFTypeRef (*wifiCreate)(CFAllocatorRef,int);
static int (*wifiState)(CFTypeRef),(*wifiDiscovery)(CFTypeRef);
static void (*wifiSet)(CFTypeRef,int),(*wifiSetDiscovery)(CFTypeRef,int);
static void (*wifiSchedule)(CFTypeRef,CFRunLoopRef,CFStringRef);
static void (*wifiUnschedule)(CFTypeRef,CFRunLoopRef,CFStringRef);
static void (*wifiSetDiscoveryExt)(CFTypeRef,CFDictionaryRef);
static CFStringRef (*wifiPassword)(CFTypeRef);
static CFArrayRef (*wifiDevices)(CFTypeRef);
static CFTypeRef (*wifiCurrentNetwork)(CFTypeRef);
static CFStringRef (*wifiInterfaceName)(CFTypeRef);

static NSArray *IHConnectedVPNServices(NSDictionary *values) {
 NSMutableSet *services=[NSMutableSet new];
 for(NSString *key in values){
  // configd的VPN状态7表示已连接；只保持来源选择，不授予转发权限。
  id value=values[key];NSArray *parts=[key componentsSeparatedByString:@"/"];
  if(parts.count==5&&[parts[0] isEqual:@"State:"]&&[parts[1] isEqual:@"Network"]&&[parts[2] isEqual:@"Service"]&&[parts[4] isEqual:@"VPN"]&&[parts[3] length]&&[value isKindOfClass:NSDictionary.class]&&[value[@"Status"] isKindOfClass:NSNumber.class]&&[value[@"Status"] intValue]==7)[services addObject:parts[3]];
 }return [services.allObjects sortedArrayUsingSelector:@selector(compare:)];
}

static BOOL IHWiFiAddressReady(void) {
 struct ifaddrs *head=NULL;if(getifaddrs(&head))return NO;BOOL ready=NO;
 for(struct ifaddrs *p=head;p;p=p->ifa_next){
  if(!p->ifa_addr||strcmp(p->ifa_name,"en0")||(p->ifa_flags&(IFF_UP|IFF_RUNNING))!=(IFF_UP|IFF_RUNNING))continue;
  if(p->ifa_addr->sa_family==AF_INET){uint32_t a=ntohl(((struct sockaddr_in*)p->ifa_addr)->sin_addr.s_addr);if(a&&(a>>16)!=0xa9fe&&(a>>24)!=127&&(a>>24)<224)ready=YES;}
  if(p->ifa_addr->sa_family==AF_INET6){struct in6_addr *a=&((struct sockaddr_in6*)p->ifa_addr)->sin6_addr;if(!IN6_IS_ADDR_UNSPECIFIED(a)&&!IN6_IS_ADDR_LINKLOCAL(a)&&!IN6_IS_ADDR_LOOPBACK(a)&&!IN6_IS_ADDR_MULTICAST(a))ready=YES;}
 }freeifaddrs(head);return ready;
}

// 可选的无线读数使用独立manager和运行循环；接口即使不返回，也不会堵住热点控制。
@interface IHWiFiReadback : NSObject
+ (instancetype)shared;
+ (instancetype)connectionShared;
- (void)read:(void (^)(NSDictionary *))completion;
@end
@implementation IHWiFiReadback {
 NSThread *_thread;CFTypeRef _manager;BOOL _busy,_connectionOnly;
}
+ (instancetype)shared {
 static IHWiFiReadback *reader;static dispatch_once_t once;
 dispatch_once(&once,^{reader=[IHWiFiReadback new];});return reader;
}
+ (instancetype)connectionShared {
 static IHWiFiReadback *reader;static dispatch_once_t once;
 dispatch_once(&once,^{reader=[[IHWiFiReadback alloc]initWithConnectionOnly:YES];});return reader;
}
- (instancetype)init {return [self initWithConnectionOnly:NO];}
- (instancetype)initWithConnectionOnly:(BOOL)connectionOnly {
 if((self=[super init])){_connectionOnly=connectionOnly;_thread=[[NSThread alloc]initWithTarget:self selector:@selector(run) object:nil];_thread.name=connectionOnly?@"iOSHotspot WiFi connection":@"iOSHotspot WiFi readback";[_thread start];}return self;
}
- (void)run {@autoreleasepool{
 if(wifiCreate&&wifiSchedule&&wifiUnschedule){_manager=wifiCreate(NULL,0);if(_manager)wifiSchedule(_manager,CFRunLoopGetCurrent(),kCFRunLoopDefaultMode);}
 NSPort *port=[NSMachPort port];[NSRunLoop.currentRunLoop addPort:port forMode:NSDefaultRunLoopMode];
 [NSRunLoop.currentRunLoop run];
 if(_manager){wifiUnschedule(_manager,CFRunLoopGetCurrent(),kCFRunLoopDefaultMode);CFRelease(_manager);_manager=NULL;}
}}
- (void)read:(void (^)(NSDictionary *))completion {
 // 同时最多一次查询，阻塞后不堆积线程或请求。
 if(_busy)return;_busy=YES;
 [self performSelector:@selector(readNow:) onThread:_thread withObject:[completion copy] waitUntilDone:NO];
}
- (void)readNow:(void (^)(NSDictionary *))completion {@autoreleasepool{
 NSMutableDictionary *values=[NSMutableDictionary new];
 if(_connectionOnly){
  // 自动选路不等待可选MIS状态或密码查询，避免一个慢读数阻塞连接变化。
  if(_manager&&wifiDevices&&wifiCurrentNetwork&&wifiInterfaceName){
   BOOL connected=NO;CFArrayRef list=wifiDevices(_manager);
   if(list){for(id item in (__bridge NSArray*)list){CFTypeRef device=(__bridge CFTypeRef)item;CFTypeRef network=wifiCurrentNetwork(device);if(network){if([(__bridge NSString*)wifiInterfaceName(device) isEqual:@"en0"])connected=YES;CFRelease(network);}}CFRelease(list);}
   values[@"wifiConnected"]=@(connected);
  }
 }else{
  if(_manager&&wifiState)values[@"wifiState"]=@(wifiState(_manager));
  if(_manager&&wifiDiscovery)values[@"discoveryState"]=@(wifiDiscovery(_manager));
  if(_manager&&wifiPassword){id value=CFBridgingRelease(wifiPassword(_manager));if([value isKindOfClass:NSString.class])values[@"password"]=value;}
  id name=copyName?CFBridgingRelease(copyName(NULL,NULL)):nil;
  if((![name isKindOfClass:NSString.class]||![name length])&&copyDeviceAnswer)name=CFBridgingRelease(copyDeviceAnswer(CFSTR("UserAssignedDeviceName")));
  if([name isKindOfClass:NSString.class])values[@"ssid"]=name;
 }
 dispatch_async(dispatch_get_main_queue(),^{self->_busy=NO;completion(values);});
}}

@end
static void storeChanged(SCDynamicStoreRef store,CFArrayRef keys,void *context) {
 IHNetwork *network=(__bridge IHNetwork*)context;[network refresh];if(network.changed)network.changed();
}
@implementation IHNetwork {
 void *_client;CFTypeRef _wifi;SCDynamicStoreRef _store;
 NSDictionary *_snapshot;NSString *_error;int _batteryToken;
 int _requestedDiscovery;BOOL _monitorsChanges;
 NSDictionary *_wifiReadback;NSDate *_credentialsReadAt;
 NSUInteger _radioGeneration;
 int _routeFD;dispatch_source_t _routeSource;

}
- (instancetype)init{return [self initWithMonitoring:YES];}
- (instancetype)initForHotspotControl{return [self initWithMonitoring:NO];}
- (instancetype)initWithMonitoring:(BOOL)monitor {
 if((self=[super init])){
  _batteryToken=-1;_routeFD=-1;_monitorsChanges=monitor;
  void *sc=dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration",RTLD_NOW);
  copyValue=dlsym(sc,"SCDynamicStoreCopyValue");copyName=dlsym(sc,"SCDynamicStoreCopyComputerName");createStore=dlsym(sc,"SCDynamicStoreCreate");setKeys=dlsym(sc,"SCDynamicStoreSetNotificationKeys");setQueue=dlsym(sc,"SCDynamicStoreSetDispatchQueue");
  copyMultiple=dlsym(sc,"SCDynamicStoreCopyMultiple");
  void *gestalt=dlopen("/usr/lib/libMobileGestalt.dylib",RTLD_LAZY);copyDeviceAnswer=gestalt?dlsym(gestalt,"MGCopyAnswer"):NULL;
  void *net=dlopen("/System/Library/PrivateFrameworks/Netrb.framework/Netrb",RTLD_NOW);netCreate=dlsym(net,"_NETRBClientCreate");netDestroy=dlsym(net,"_NETRBClientDestroy");netSet=dlsym(net,"_NETRBClientSetGlobalServiceState");netGet=dlsym(net,"_NETRBClientGetGlobalServiceState");
  void *wifi=dlopen("/System/Library/PrivateFrameworks/MobileWiFi.framework/MobileWiFi",RTLD_NOW);wifiCreate=dlsym(wifi,"WiFiManagerClientCreate");wifiState=dlsym(wifi,"WiFiManagerClientGetMISState");wifiDiscovery=dlsym(wifi,"WiFiManagerClientGetMISDiscoveryState");wifiSet=dlsym(wifi,"WiFiManagerClientSetMISState");wifiSetDiscovery=dlsym(wifi,"WiFiManagerClientSetMISDiscoveryState");wifiPassword=dlsym(wifi,"WiFiManagerClientCopyMisPassword");
  wifiSchedule=dlsym(wifi,"WiFiManagerClientScheduleWithRunLoop");wifiUnschedule=dlsym(wifi,"WiFiManagerClientUnscheduleFromRunLoop");wifiSetDiscoveryExt=dlsym(wifi,"WiFiManagerClientSetMISDiscoveryStateExt");
  wifiDevices=dlsym(wifi,"WiFiManagerClientCopyDevices");wifiCurrentNetwork=dlsym(wifi,"WiFiDeviceClientCopyCurrentNetwork");wifiInterfaceName=dlsym(wifi,"WiFiDeviceClientGetInterfaceName");
  if(netCreate)_client=netCreate(dispatch_get_main_queue(),nil,0);if(wifiCreate&&wifiSchedule&&wifiUnschedule)_wifi=wifiCreate(NULL,0);
  // Frida已核实：未调度manager时直接调用setter返回成功但不会启动ap1。
  if(_wifi&&wifiSchedule){wifiSchedule(_wifi,CFRunLoopGetCurrent(),kCFRunLoopDefaultMode);}
  if(!_client||!netSet||!copyValue)_error=@"当前系统的原生热点后端或授权不可用，未修改网络。";
  if(monitor&&createStore&&setKeys&&setQueue){SCDynamicStoreContext context={0,(__bridge void*)self,NULL,NULL,NULL};_store=createStore(NULL,CFSTR("iOSHotspot"),storeChanged,&context);if(_store){setKeys(_store,(__bridge CFArrayRef)@[@"com.apple.MobileInternetSharing"],(__bridge CFArrayRef)@[@"State:/Network/.*",@"Setup:/Network/.*"]);setQueue(_store,dispatch_get_main_queue());}}
  if(monitor){__weak IHNetwork *weak=self;notify_register_dispatch("com.apple.system.powersources.source",&_batteryToken,dispatch_get_main_queue(),^(int token){if(weak.changed)weak.changed();});}
  // 路由就绪可能晚于VPN地址发布，自动来源也订阅只读路由事件，不在关闭时轮询。
  if(monitor){
   _routeFD=socket(PF_ROUTE,SOCK_RAW,0);
   if(_routeFD>=0&&fcntl(_routeFD,F_SETFL,O_NONBLOCK)==0){
    _routeSource=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,_routeFD,0,dispatch_get_main_queue());__weak IHNetwork *weak=self;
    dispatch_source_set_event_handler(_routeSource,^{IHNetwork *strong=weak;if(!strong)return;uint8_t buffer[8192];ssize_t count;BOOL relevant=NO;
     while((count=read(strong->_routeFD,buffer,sizeof(buffer)))>0)for(size_t offset=0;offset+4<=(size_t)count;){uint16_t size;memcpy(&size,buffer+offset,2);if(size<4||size>(size_t)count-offset)break;if(buffer[offset+2]==5&&buffer[offset+3]!=4)relevant=YES;offset+=size;}
     if(relevant){[strong refresh];if(strong.changed)strong.changed();}
    });int routeFD=_routeFD;dispatch_source_set_cancel_handler(_routeSource,^{close(routeFD);});dispatch_resume(_routeSource);
   }else if(_routeFD>=0){close(_routeFD);_routeFD=-1;}
  }
  [self refresh];
 }return self;
}
- (void)dealloc {if(_routeSource){dispatch_source_cancel(_routeSource);}if(_store){if(setQueue)setQueue(_store,NULL);CFRelease(_store);}if(_wifi){if(wifiUnschedule)wifiUnschedule(_wifi,CFRunLoopGetMain(),kCFRunLoopDefaultMode);CFRelease(_wifi);}if(_client&&netDestroy)netDestroy(_client);if(_batteryToken>=0)notify_cancel(_batteryToken);}

- (BOOL)available{return !_error;}
- (NSString*)error{return _error?:@"";}
- (NSDictionary*)snapshot{return _snapshot?:@{};}
- (BOOL)setGlobalState:(int)state {
 if(_client&&netSet&&netSet(_client,state))return YES;
 // misd 重新加载后旧客户端句柄失效，重建控制连接；不重启无线接口。
 if(_client&&netDestroy)netDestroy(_client);_client=netCreate?netCreate(dispatch_get_main_queue(),nil,0):NULL;
 if(_client&&netSet&&netSet(_client,state))return YES;
 // 已关闭是可核实的幂等结果，不能将已开启状态当作新会话启动成功。
 return state==1022&&[[self valueForKeyPath:@"com.apple.MobileInternetSharing"][@"UState"] intValue]==1022;
}
- (NSDictionary*)valueForKeyPath:(NSString*)key {
    if(!copyValue)return @{}; CFPropertyListRef value=copyValue(_store,(__bridge CFStringRef)key);
    id result=CFBridgingRelease(value);return [result isKindOfClass:NSDictionary.class]?result:@{};
}
- (void)refresh {
    NSDictionary *sharing=[self valueForKeyPath:@"com.apple.MobileInternetSharing"];
    NSDictionary *hosts=[sharing[@"Hosts"] isKindOfClass:NSDictionary.class]?sharing[@"Hosts"]:@{};
    NSDictionary *ipv4=[self valueForKeyPath:@"State:/Network/Global/IPv4"];
    NSDictionary *ipv6=[self valueForKeyPath:@"State:/Network/Global/IPv6"];
    BOOL wifiConnected=[_wifiReadback[@"wifiConnected"] boolValue]&&IHWiFiAddressReady();
    NSDictionary *vpnValues=copyMultiple?CFBridgingRelease(copyMultiple(_store,NULL,(__bridge CFArrayRef)@[@"State:/Network/Service/.*/VPN"])):nil;
    NSArray *vpnServices=IHConnectedVPNServices(vpnValues);
    BOOL vpnConnected=vpnServices.count||IHKernelVPNName(ipv4[@"PrimaryInterface"])||IHKernelVPNName(ipv6[@"PrimaryInterface"]);
    int state=[sharing[@"State"] intValue], reason=[sharing[@"Reason"] intValue];
    // 所有系统统一使用SC作为开关依据；可选MIS读数按实际导出能力异步取得。
    int wifi=_wifiReadback[@"wifiState"]?[_wifiReadback[@"wifiState"] intValue]:([sharing[@"UState"] intValue]==1023?1:0);
    int discovery=_wifiReadback[@"discoveryState"]?[_wifiReadback[@"discoveryState"] intValue]:_requestedDiscovery;
    if(_monitorsChanges&&(!_credentialsReadAt||[NSDate.date timeIntervalSinceDate:_credentialsReadAt]>=2)){
     _credentialsReadAt=NSDate.date;NSUInteger generation=_radioGeneration;__weak IHNetwork *weak=self;
     void (^completion)(NSDictionary*)=^(NSDictionary *values){IHNetwork *strong=weak;if(!strong||generation!=strong->_radioGeneration)return;
      NSMutableDictionary *updated=[strong->_wifiReadback mutableCopy]?:[NSMutableDictionary new];[updated addEntriesFromDictionary:values];
      if([strong->_wifiReadback isEqual:updated])return;strong->_wifiReadback=updated;[strong refresh];if(strong.changed)strong.changed();};
     [IHWiFiReadback.shared read:completion];[IHWiFiReadback.connectionShared read:completion];
    }
    NSString *ssid=_wifiReadback[@"ssid"]?:@"",*password=_wifiReadback[@"password"]?:@"";
    NSArray *external=[sharing[@"ExternalInterfaces"] isKindOfClass:NSArray.class]?sharing[@"ExternalInterfaces"]:@[];
    NSArray *internal=[sharing[@"InternalInterfaces"] isKindOfClass:NSArray.class]?sharing[@"InternalInterfaces"]:@[];
    NSMutableArray *names=[NSMutableArray array];
    for(id item in external){if([item isKindOfClass:NSString.class])[names addObject:item];else if([item isKindOfClass:NSDictionary.class])for(NSString *key in @[@"InterfaceName",@"Name",@"interfaceName"])if([item[key] isKindOfClass:NSString.class]){[names addObject:item[key]];break;}}
    BOOL requested=[sharing[@"UState"] intValue]==1023;
    BOOL on=requested&&!IHSharingIsUnavailableEmpty(sharing);
    BOOL active=internal.count>0 && wifi>0;
    _snapshot=@{@"wifiConnected":@(wifiConnected),@"vpnConnected":@(vpnConnected),@"hotspotOn":@(on),@"hotspotRequested":@(requested),@"active":@(active),@"state":@(state),@"reason":@(reason),@"wifiState":@(wifi),@"discoveryState":@(discovery),@"ssid":ssid?:@"",@"password":password?:@"",@"clientCount":hosts[@"Current"]?:@0,@"maxClients":hosts[@"Max"]?:@0,@"transportCounts":hosts[@"Type"]?:@{},@"externalInterfaces":external,@"internalInterfaces":internal,@"upstream":[names componentsJoinedByString:@", "],@"primaryInterface":ipv4[@"PrimaryInterface"]?:@"",@"sharing":sharing};
    NSMutableDictionary *withVPN=[_snapshot mutableCopy];withVPN[@"connectedVPNServiceIDs"]=vpnServices;_snapshot=withVPN;
}
- (BOOL)setHotspot:(BOOL)on error:(NSError**)error {
    if(!self.available){if(error)*error=[NSError errorWithDomain:@"iOSHotspot" code:1 userInfo:@{NSLocalizedDescriptionKey:self.error}];return NO;}
    // 该 ABI 已用指定 iOS16.2 的 REA 代码与只读 probe 核实；结果再以系统状态确认。
    if(![self setGlobalState:on?1023:1022]){if(error)*error=[NSError errorWithDomain:@"iOSHotspot" code:2 userInfo:@{NSLocalizedDescriptionKey:@"系统拒绝修改热点状态。"}];return NO;}
    // 系统原生开关仅发Netrb状态；不再直接强设Wi-Fi MIS状态。
    if(_wifi&&wifiSetDiscovery)wifiSetDiscovery(_wifi,on?1:0);
    _requestedDiscovery=on?1:0;
    _radioGeneration++;NSMutableDictionary *cached=[_wifiReadback mutableCopy];[cached removeObjectsForKeys:@[@"wifiState",@"discoveryState"]];_wifiReadback=cached;
    if(!on){
     // 关闭请求返回时USB组件可能仍在销毁服务，必须等待其完成后才能切换来源。
     BOOL stopped=NO;double deadline=IHMonotonicTime()+IHRadioStopTimeout;do{
      NSDictionary *value=[self valueForKeyPath:@"com.apple.MobileInternetSharing"];
      if(IHSharingIsStopped(value)){stopped=YES;break;}
      usleep(50000);
     }while(IHMonotonicTime()<deadline);
     if(!stopped){[self refresh];if(error)*error=[NSError errorWithDomain:@"iOSHotspot" code:4 userInfo:@{NSLocalizedDescriptionKey:@"系统仍在关闭共享接口，请稍后再切换来源。"}];return NO;}
    }
    if(on&&_wifi&&wifiSetDiscoveryExt){
     // 只打开原生发现状态，不强设频段；最大兼容性继续由系统保存的用户选项决定。
     NSDictionary *options=@{@"SOFTAP_ENABLE":@YES,@"SOFTAP_IMMEDIATE_DISABLE":@YES};wifiSetDiscoveryExt(_wifi,(__bridge CFDictionaryRef)options);
    }
    [self refresh];return YES;
}
- (NSDictionary*)captureBaseline {
    [self refresh];return @{@"state":[_snapshot[@"hotspotOn"] boolValue]?@1023:@1022,@"wifiState":_snapshot[@"wifiState"],@"discoveryState":_snapshot[@"discoveryState"],@"hotspotOn":_snapshot[@"hotspotOn"]};
}
- (BOOL)restoreBaseline:(NSDictionary*)baseline error:(NSError**)error {
    if(!self.available)return NO;
    BOOL success=[self setGlobalState:[baseline[@"state"] intValue]];
    if(_wifi&&wifiSetDiscovery)wifiSetDiscovery(_wifi,[baseline[@"discoveryState"] intValue]);
    _requestedDiscovery=[baseline[@"discoveryState"] intValue];
    [self refresh];if(!success&&error)*error=[NSError errorWithDomain:@"iOSHotspot" code:3 userInfo:@{NSLocalizedDescriptionKey:@"原生热点状态回滚失败；已保留恢复日志。"}];return success;
}
- (NSDictionary*)interfaceCounters {
    NSMutableDictionary *result=[NSMutableDictionary dictionary];
    // NET_RT_IFLIST2 返回内核64位计数，避免4GiB回绕造成漏记。
    int mib[6]={CTL_NET,PF_ROUTE,0,0,NET_RT_IFLIST2,0};size_t length=0;
    if(sysctl(mib,6,NULL,&length,NULL,0)!=0||length==0||length>16*1024*1024)return result;
    NSMutableData *data=[NSMutableData dataWithLength:length];if(sysctl(mib,6,data.mutableBytes,&length,NULL,0)!=0)return result;
    uint8_t *cursor=data.mutableBytes,*end=cursor+length;
    while(cursor+4<=end){uint16_t size;memcpy(&size,cursor,2);if(size<4||cursor+size>end)break;
        if(cursor[3]==0x12 && size>=sizeof(struct if_msghdr2)){struct if_msghdr2 *message=(void*)cursor;char name[IFNAMSIZ]={0};
            if(if_indextoname(message->ifm_index,name))result[@(name)]=@{@"rx":@(message->ifm_data.ifi_ibytes),@"tx":@(message->ifm_data.ifi_obytes),@"flags":@(message->ifm_flags)};
        }cursor+=size;
    }return result;
}
- (NSInteger)batteryPercent {
    // 通过 IOKit 读取真实电池容量，不依赖需前台的 UIDevice 定时读取。
    void *io=dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",RTLD_LAZY);
    uint32_t(*get)(uint32_t,CFDictionaryRef)=dlsym(io,"IOServiceGetMatchingService");
    CFMutableDictionaryRef(*matching)(const char*)=dlsym(io,"IOServiceMatching");
    CFTypeRef(*property)(uint32_t,CFStringRef,CFAllocatorRef,uint32_t)=dlsym(io,"IORegistryEntryCreateCFProperty");
    int(*release)(uint32_t)=dlsym(io,"IOObjectRelease");
    if(!get||!matching||!property||!release)return -1;
    uint32_t service=get(0,matching("AppleSmartBattery"));if(!service)return -1;
    NSNumber *capacity=CFBridgingRelease(property(service,CFSTR("CurrentCapacity"),NULL,0));
    NSNumber *max=CFBridgingRelease(property(service,CFSTR("MaxCapacity"),NULL,0));release(service);
    if(!capacity||!max||max.doubleValue<=0)return -1;
    return (NSInteger)llround(100*capacity.doubleValue/max.doubleValue);
}
@end
