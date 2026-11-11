#import "WiFiPrefix.h"
#import "../common/IHNativeVPNProtocol.h"
#import "../common/IHWiFiPrefixProtocol.h"
#include <objc/runtime.h>
#include <dispatch/dispatch.h>
#include <ifaddrs.h>
#include <sys/time.h>

// 与具名misCTClientSharedInstance方法核实的输出ABI；不访问misd内部对象布局。
typedef struct {uint8_t carrier,user,available,reserved;uint32_t maxHosts,state;int32_t context;char interfaceName[16];} IHWiFiTetherStatus;
_Static_assert(sizeof(IHWiFiTetherStatus)==32,"tethering status ABI不符");
typedef void (*IHWiFiEventCallback)(int,const IHWiFiTetherStatus *,void *);
@interface IHWiFiPrefixOwner:NSObject
@property(nonatomic) IHWiFiEventCallback callback;
@property(nonatomic) void *argument;
@property(nonatomic,strong) dispatch_queue_t queue;
@property(nonatomic) unsigned interfaceIndex;
@end
@implementation IHWiFiPrefixOwner @end

// libpcap使用稳定公开ABI，只读取IPv6固定头与NDP控制目标，不读取应用负载。
typedef struct IHWiFiPcap IHWiFiPcap;
typedef struct {unsigned length;void *instructions;} IHWiFiBPFProgram;
typedef struct {struct timeval time;uint32_t capturedLength,length;} IHWiFiPacketHeader;
static IHWiFiPcap *(*pcapOpen)(const char*,int,int,int,char*);
static int (*pcapCompile)(IHWiFiPcap*,IHWiFiBPFProgram*,const char*,int,uint32_t);
static int (*pcapFilter)(IHWiFiPcap*,IHWiFiBPFProgram*);
static void (*pcapFree)(IHWiFiBPFProgram*);
static int (*pcapNonblock)(IHWiFiPcap*,int,char*),(*pcapDatalink)(IHWiFiPcap*),(*pcapDescriptor)(IHWiFiPcap*);
static int (*pcapNext)(IHWiFiPcap*,IHWiFiPacketHeader**,const unsigned char**);
static void (*pcapClose)(IHWiFiPcap*);
@interface IHWiFiPrefixCapture:NSObject
@property(nonatomic) IHWiFiPcap *handle;
@property(nonatomic) unsigned offset;
@property(nonatomic,strong) dispatch_source_t source;
@end
@implementation IHWiFiPrefixCapture @end

static NSObject *stateLock;
static IHWiFiPrefixOwner *owner;
static BOOL ready,retiredRegistration;
static dispatch_queue_t monitorQueue;
static NSMutableArray<IHWiFiPrefixCapture*> *captures;
static NSMutableDictionary<NSData*,NSNumber*> *groups;
static NSData *allowedPrefixes;
static int membershipSocket=-1;
static unsigned monitoredIndex;
static NSString *lastError=@"";
static BOOL (*originalRegister)(id,SEL,BOOL,void*,void*);
static int (*originalActivate)(id,SEL,BOOL),(*originalName)(id,SEL,char*),(*originalStatus)(id,SEL,IHWiFiTetherStatus*);

static IHWiFiPrefixOwner *currentOwner(void){@synchronized(stateLock){return owner;}}
static BOOL wifiPolicy(void){
 NSDictionary *runtime=IHNativeReadJSON(IHSourceRuntimePath);
 if(![runtime[@"version"] isEqual:@1]||![runtime[@"enabled"] isEqual:@YES]||![runtime[@"source"] isEqual:@"wifi"]||![runtime[@"upstream"] isEqual:@"en0"])return NO;
 struct stat file;struct timeval boot={0};size_t size=sizeof(boot);int mib[]={CTL_KERN,KERN_BOOTTIME};
 return !lstat(IHSourceRuntimePath.fileSystemRepresentation,&file)&&!sysctl(mib,2,&boot,&size,NULL,0)&&file.st_mtimespec.tv_sec>=boot.tv_sec;
}
static unsigned wifiInterface(void){
 struct ifaddrs *head=NULL;if(getifaddrs(&head))return 0;BOOL usable=NO;
 for(struct ifaddrs *p=head;p;p=p->ifa_next){
  if(!p->ifa_addr||strcmp(p->ifa_name,"en0")||(p->ifa_flags&(IFF_UP|IFF_RUNNING))!=(IFF_UP|IFF_RUNNING))continue;
  if(p->ifa_addr->sa_family==AF_INET){uint32_t a=ntohl(((struct sockaddr_in*)p->ifa_addr)->sin_addr.s_addr);if(a&&(a>>24)!=127&&(a>>16)!=0xa9fe)usable=YES;}
  if(p->ifa_addr->sa_family==AF_INET6){struct in6_addr *a=&((struct sockaddr_in6*)p->ifa_addr)->sin6_addr;if(!IN6_IS_ADDR_UNSPECIFIED(a)&&!IN6_IS_ADDR_LINKLOCAL(a)&&!IN6_IS_ADDR_MULTICAST(a)&&!IN6_IS_ADDR_LOOPBACK(a))usable=YES;}
 }
 freeifaddrs(head);return usable?if_nametoindex("en0"):0;
}
static void fillStatus(IHWiFiTetherStatus *status,unsigned index){
 memset(status,0,sizeof(*status));status->carrier=1;status->user=1;status->available=index!=0;status->maxHosts=3;status->state=index?3:1;status->context=-1;
 if(index)strlcpy(status->interfaceName,"en0",sizeof(status->interfaceName));
}
static void writeState(void){
 NSDictionary *value=@{@"ready":@(ready),@"active":@(currentOwner()!=nil),@"packageVersion":@(IH_BUILD_VERSION),@"sourcePolicyBuild":@(IHSourcePolicyBuild),@"pid":@(getpid()),@"interfaceIndex":@(monitoredIndex),@"monitoredBridges":@(captures.count),@"memberships":@(groups.count),@"lastError":lastError?:@"",@"time":@(NSDate.date.timeIntervalSince1970)};
 IHNativeWriteRuntimeJSON(IHWiFiPrefixStatePath,value);
}
// 本队列独占pcap对象、套接字与订阅集合；关闭和读取不会并发。
static void stopMonitoring(void){
 for(IHWiFiPrefixCapture *capture in captures){if(capture.source)dispatch_source_cancel(capture.source);if(capture.handle){pcapClose(capture.handle);capture.handle=NULL;}}
 [captures removeAllObjects];if(membershipSocket>=0)close(membershipSocket);membershipSocket=-1;[groups removeAllObjects];allowedPrefixes=nil;monitoredIndex=0;
}
static NSData *copyPrefixes(void){
 struct ifaddrs *head=NULL;if(getifaddrs(&head))return nil;NSMutableData *prefixes=[NSMutableData new];
 for(struct ifaddrs *p=head;p;p=p->ifa_next){
  if(!p->ifa_addr||!p->ifa_netmask||strcmp(p->ifa_name,"en0")||p->ifa_addr->sa_family!=AF_INET6)continue;
  const uint8_t *a=((struct sockaddr_in6*)p->ifa_addr)->sin6_addr.s6_addr,*mask=((struct sockaddr_in6*)p->ifa_netmask)->sin6_addr.s6_addr;
  if((a[0]&0xe0)!=0x20)continue;BOOL full=YES;for(int i=0;i<16;i++)if(mask[i]!=(i<8?255:0))full=NO;if(!full)continue;
  BOOL exists=NO;for(NSUInteger i=0;i<prefixes.length;i+=8)if(!memcmp((const uint8_t*)prefixes.bytes+i,a,8))exists=YES;
  if(!exists)[prefixes appendBytes:a length:8];
 }freeifaddrs(head);return prefixes;
}
static void joinAddress(const uint8_t address[16]){
 uint8_t multicast[16];if(!IHWiFiSolicitedGroup(address,allowedPrefixes.bytes,allowedPrefixes.length/8,multicast))return;
 NSData *key=[NSData dataWithBytes:multicast length:16];if(groups[key]){groups[key]=@(NSDate.date.timeIntervalSince1970);return;}
 struct ipv6_mreq request={0};memcpy(&request.ipv6mr_multiaddr,multicast,16);request.ipv6mr_interface=monitoredIndex;
 if(groups.count>=1024){
  NSData *oldest=[[groups keysSortedByValueUsingSelector:@selector(compare:)] firstObject];struct ipv6_mreq previous={0};memcpy(&previous.ipv6mr_multiaddr,oldest.bytes,16);previous.ipv6mr_interface=monitoredIndex;
  if(setsockopt(membershipSocket,IPPROTO_IPV6,IPV6_LEAVE_GROUP,&previous,sizeof(previous))){lastError=@"无法释放旧IPv6组播订阅";writeState();return;}[groups removeObjectForKey:oldest];
 }
 if(setsockopt(membershipSocket,IPPROTO_IPV6,IPV6_JOIN_GROUP,&request,sizeof(request))){lastError=[NSString stringWithFormat:@"IPv6组播订阅失败（%d）",errno];writeState();return;}
 groups[key]=@(NSDate.date.timeIntervalSince1970);lastError=@"";writeState();
}
static void readPackets(IHWiFiPrefixCapture *capture,IHWiFiPrefixOwner *expected){@autoreleasepool{
 if(!capture.handle)return;
 if(currentOwner()!=expected||!wifiPolicy()||if_nametoindex("en0")!=expected.interfaceIndex){stopMonitoring();writeState();return;}
 for(unsigned i=0;i<128;i++){
  IHWiFiPacketHeader *header=NULL;const unsigned char *packet=NULL;int result=pcapNext(capture.handle,&header,&packet);
  if(!result)break;if(result<0){lastError=@"热点IPv6头监听中断";stopMonitoring();writeState();break;}
  if(!header||!packet||header->capturedLength<capture.offset+40)continue;const unsigned char *ip=packet+capture.offset;if((ip[0]>>4)!=6)continue;
  joinAddress(ip+8);
  if(header->capturedLength>=capture.offset+64&&ip[6]==58&&(ip[40]==135||ip[40]==136))joinAddress(ip+48);
 }
}}
static NSArray<NSString*> *advertisedBridges(void){
 const char *path="/Library/Preferences/SystemConfiguration/com.apple.mis.rtadvd.conf";int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return nil;struct stat st;
 if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||st.st_size<1||st.st_size>32768){close(fd);return nil;}
 NSMutableData *data=[NSMutableData dataWithLength:(NSUInteger)st.st_size];size_t offset=0;
 while(offset<data.length){ssize_t n=read(fd,(char*)data.mutableBytes+offset,data.length-offset);if(n<0&&errno==EINTR)continue;if(n<=0){close(fd);return nil;}offset+=(size_t)n;}close(fd);
 NSString *text=[[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];if(!text)return nil;NSMutableArray *names=[NSMutableArray new];
 for(NSString *line in [text componentsSeparatedByString:@"\n"]){
  NSRange colon=[line rangeOfString:@":"];if(colon.location==NSNotFound)continue;NSString *name=[line substringToIndex:colon.location];
  if([name hasPrefix:@"bridge"]&&IHNativeInterfaceName(name)&&if_nametoindex(name.UTF8String)&&![names containsObject:name])[names addObject:name];
 }
 return names;
}
BOOL IHWiFiPrefixPrepareRA(void){
 IHWiFiPrefixOwner *expected=currentOwner();if(!expected)return YES;__block BOOL okay=NO;
 dispatch_sync(monitorQueue,^{@autoreleasepool{
  stopMonitoring();lastError=@"";
  if(!wifiPolicy()||wifiInterface()!=expected.interfaceIndex){lastError=@"Wi-Fi上游身份已变化";writeState();return;}
  allowedPrefixes=copyPrefixes();if(!allowedPrefixes.length){okay=YES;writeState();return;}
  NSArray<NSString*> *names=advertisedBridges();if(!names.count){lastError=@"未找到本轮原生IPv6通告接口";writeState();return;}
  membershipSocket=socket(AF_INET6,SOCK_DGRAM,0);if(membershipSocket<0){lastError=@"无法创建IPv6组播订阅套接字";writeState();return;}
  fcntl(membershipSocket,F_SETFD,FD_CLOEXEC);monitoredIndex=expected.interfaceIndex;
  for(NSString *name in names){
   char error[256]={0};IHWiFiPcap *handle=pcapOpen(name.UTF8String,86,0,1,error);if(!handle){lastError=@"无法监听热点IPv6头";break;}
   int link=pcapDatalink(handle),descriptor=pcapDescriptor(handle);if(descriptor>=0)fcntl(descriptor,F_SETFD,FD_CLOEXEC);IHWiFiBPFProgram program={0};
   if((link!=0&&link!=1&&link!=12)||descriptor<0||pcapCompile(handle,&program,"ip6",1,UINT32_MAX)){pcapClose(handle);lastError=@"热点IPv6监听格式不受支持";break;}
   int code=pcapFilter(handle,&program);pcapFree(&program);if(code||pcapNonblock(handle,1,error)){pcapClose(handle);lastError=@"无法启用热点IPv6头监听";break;}
   IHWiFiPrefixCapture *capture=[IHWiFiPrefixCapture new];capture.handle=handle;capture.offset=link==1?14:link==0?4:0;
   capture.source=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,(uintptr_t)descriptor,0,monitorQueue);if(!capture.source){pcapClose(handle);lastError=@"无法创建IPv6监听事件";break;}
   [captures addObject:capture];__weak IHWiFiPrefixCapture *weak=capture;
   dispatch_source_set_event_handler(capture.source,^{IHWiFiPrefixCapture *strong=weak;if(strong)readPackets(strong,expected);});dispatch_resume(capture.source);
  }
  okay=!lastError.length&&captures.count==names.count;
  // rtadvd要求先开启IPv6转发，否则子进程虽成功派生却会立即退出。
  if(okay){
   int forwarding=-1;size_t size=sizeof(forwarding);
   okay=!IHNativeSetForwarding(AF_INET6,1)&&!sysctlbyname("net.inet6.ip6.forwarding",&forwarding,&size,NULL,0)&&forwarding==1;
   if(!okay)lastError=@"IPv6转发尚未就绪，未启动路由通告";
  }
  if(!okay)stopMonitoring();writeState();
 }});return okay;
}
static BOOL registerWiFi(id self,SEL selector,BOOL enable,void *callback,void *argument){
 if(enable&&wifiPolicy()){
  unsigned index=wifiInterface();if(!index||!callback||!argument)return NO;
  IHWiFiPrefixOwner *next=[IHWiFiPrefixOwner new];next.callback=(IHWiFiEventCallback)callback;next.argument=argument;next.interfaceIndex=index;next.queue=dispatch_get_current_queue();
  @synchronized(stateLock){if(owner)return NO;owner=next;retiredRegistration=NO;}
  dispatch_sync(monitorQueue,^{writeState();});return YES;
 }
 if(!enable&&currentOwner()){
  @synchronized(stateLock){owner=nil;retiredRegistration=YES;}
  dispatch_sync(monitorQueue,^{stopMonitoring();writeState();});return YES;
 }
 if(enable)@synchronized(stateLock){retiredRegistration=NO;}
 return originalRegister(self,selector,enable,callback,argument);
}
static int activateWiFi(id self,SEL selector,BOOL enable){
 IHWiFiPrefixOwner *expected=currentOwner();BOOL retired;@synchronized(stateLock){retired=retiredRegistration;}
 if(!expected){if(!enable&&retired)return 0;return originalActivate(self,selector,enable);}
 if(enable){
  dispatch_async(expected.queue,^{if(currentOwner()!=expected||!wifiPolicy())return;unsigned index=wifiInterface();IHWiFiTetherStatus status;fillStatus(&status,index==expected.interfaceIndex?index:0);expected.callback(1,&status,expected.argument);});
 }else dispatch_sync(monitorQueue,^{stopMonitoring();writeState();});
 return 0;
}
static int nameWiFi(id self,SEL selector,char *name){
 IHWiFiPrefixOwner *expected=currentOwner();if(expected||wifiPolicy()){unsigned index=wifiInterface();if(!index||(expected&&index!=expected.interfaceIndex))return -1;strlcpy(name,"en0",16);return 0;}
 return originalName(self,selector,name);
}
static int statusWiFi(id self,SEL selector,IHWiFiTetherStatus *status){
 IHWiFiPrefixOwner *expected=currentOwner();if(expected||wifiPolicy()){unsigned index=wifiInterface();fillStatus(status,expected&&index!=expected.interfaceIndex?0:index);return 0;}
 return originalStatus(self,selector,status);
}
void IHWiFiPrefixFilter(int *name,unsigned count,void *value,size_t *length,size_t capacity){
 if(count!=4||!name||name[0]!=CTL_NET||name[1]!=AF_INET6||name[2]!=IPPROTO_ICMPV6||name[3]!=20||!value||!length)return;
 IHWiFiPrefixOwner *expected=currentOwner();if(expected&&wifiPolicy()&&wifiInterface()==expected.interfaceIndex)IHWiFiPreferGlobalPrefixes(value,length,capacity,expected.interfaceIndex);
}
BOOL IHWiFiPrefixIsReady(void){return ready;}
static BOOL argumentMatches(Method method,unsigned index,const char *allowed){char *type=method_copyArgumentType(method,index);BOOL match=type&&strchr(allowed,*type);free(type);return match;}
BOOL IHWiFiPrefixInstall(void){
 if(ready)return YES;
 stateLock=[NSObject new];monitorQueue=dispatch_queue_create("com.newbie.ioshotspot.wifi-prefix",DISPATCH_QUEUE_SERIAL);captures=[NSMutableArray new];groups=[NSMutableDictionary new];
 void *library=dlopen("/usr/lib/libpcap.A.dylib",RTLD_NOW);void (*hook)(Class,SEL,IMP,IMP*)=dlsym(RTLD_DEFAULT,"MSHookMessageEx");Class cls=objc_getClass("misCTClientSharedInstance");
 struct{const char *name;void **target;} symbols[]={
  {"pcap_open_live",(void**)&pcapOpen},{"pcap_compile",(void**)&pcapCompile},{"pcap_setfilter",(void**)&pcapFilter},{"pcap_freecode",(void**)&pcapFree},{"pcap_setnonblock",(void**)&pcapNonblock},{"pcap_datalink",(void**)&pcapDatalink},{"pcap_get_selectable_fd",(void**)&pcapDescriptor},{"pcap_next_ex",(void**)&pcapNext},{"pcap_close",(void**)&pcapClose}};
 BOOL supported=library&&hook&&cls&&dlsym(RTLD_DEFAULT,"dispatch_get_current_queue");for(size_t i=0;i<sizeof(symbols)/sizeof(symbols[0]);i++){*symbols[i].target=library?dlsym(library,symbols[i].name):NULL;if(!*symbols[i].target)supported=NO;}
 struct{const char *selector;IMP replacement;IMP *original;unsigned count;const char *result;} methods[]={
  {"registerCellularDataStatusNotification:callback:callbackArg:",(IMP)registerWiFi,(IMP*)&originalRegister,5,"Bc"},
  {"activateTethering:",(IMP)activateWiFi,(IMP*)&originalActivate,3,"i"},{"getTetheringInterfaceName:",(IMP)nameWiFi,(IMP*)&originalName,3,"i"},{"getTetheringStatus:",(IMP)statusWiFi,(IMP*)&originalStatus,3,"i"}};
 for(size_t i=0;i<sizeof(methods)/sizeof(methods[0]);i++){
  Method method=cls?class_getInstanceMethod(cls,sel_registerName(methods[i].selector)):NULL;char *result=method?method_copyReturnType(method):NULL;
  if(!method||method_getNumberOfArguments(method)!=methods[i].count||!result||!strchr(methods[i].result,*result)||!argumentMatches(method,2,i<2?"Bc":"^*"))supported=NO;
  if(i==0&&method&&(!argumentMatches(method,3,"^")||!argumentMatches(method,4,"^")))supported=NO;free(result);
 }
 if(supported){for(size_t i=0;i<sizeof(methods)/sizeof(methods[0]);i++){hook(cls,sel_registerName(methods[i].selector),methods[i].replacement,methods[i].original);if(!*methods[i].original)supported=NO;}}
 ready=supported;if(!ready)lastError=@"原生Wi-Fi前缀共享所需具名接口不完整";dispatch_sync(monitorQueue,^{writeState();});return ready;
}
