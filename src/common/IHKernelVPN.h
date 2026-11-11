#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>

// 只读系统实际主隧道、服务映射和接口地址；不调用私有NE会话或修改路由/PF。
static NSDictionary *IHKernelVPNStore(NSString *key) {
 typedef const void *(*CopyValue)(const void *,const void *);
 static CopyValue copy;static dispatch_once_t once;
 dispatch_once(&once,^{void *image=dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration",RTLD_LAZY);copy=image?(CopyValue)dlsym(image,"SCDynamicStoreCopyValue"):NULL;});
 if(!copy)return @{};id value=CFBridgingRelease(copy(NULL,(__bridge const void *)key));
 return [value isKindOfClass:NSDictionary.class]?value:@{};
}
static BOOL IHKernelVPNName(NSString *name) {
 return [name isKindOfClass:NSString.class]&&[name hasPrefix:@"utun"]&&name.length>4&&name.length<IFNAMSIZ&&
 [[name substringFromIndex:4] rangeOfCharacterFromSet:NSCharacterSet.decimalDigitCharacterSet.invertedSet].location==NSNotFound;
}
static NSDictionary *IHKernelVPNBinding(void) {
 NSDictionary *global=IHKernelVPNStore(@"State:/Network/Global/IPv4");
 NSString *name=global[@"PrimaryInterface"],*service=global[@"PrimaryService"];
 if(!IHKernelVPNName(name)||![service isKindOfClass:NSString.class]||!service.length||service.length>128)return @{};
 NSDictionary *mapping=IHKernelVPNStore([NSString stringWithFormat:@"State:/Network/Service/%@/IPv4",service]);
 if(![mapping[@"InterfaceName"] isEqual:name])return @{};
 unsigned index=if_nametoindex(name.UTF8String);if(!index)return @{};
 struct ifaddrs *head=NULL;if(getifaddrs(&head))return @{};
 NSMutableArray *addresses=[NSMutableArray array],*ipv6=[NSMutableArray array];
 for(struct ifaddrs *item=head;item;item=item->ifa_next){
  if(!item->ifa_addr||strcmp(item->ifa_name,name.UTF8String)||
     !(item->ifa_flags&IFF_UP)||!(item->ifa_flags&IFF_RUNNING)||!(item->ifa_flags&IFF_POINTOPOINT))continue;
  if(item->ifa_addr->sa_family==AF_INET6){struct in6_addr ip=((struct sockaddr_in6*)item->ifa_addr)->sin6_addr;
   if(!IN6_IS_ADDR_UNSPECIFIED(&ip)&&!IN6_IS_ADDR_LOOPBACK(&ip)&&!IN6_IS_ADDR_LINKLOCAL(&ip)&&!IN6_IS_ADDR_MULTICAST(&ip)&&!IN6_IS_ADDR_V4MAPPED(&ip)){
    char buffer[INET6_ADDRSTRLEN];if(inet_ntop(AF_INET6,&ip,buffer,sizeof(buffer)))[ipv6 addObject:@(buffer)];}continue;}
  if(item->ifa_addr->sa_family!=AF_INET)continue;
  struct in_addr ip=((struct sockaddr_in*)item->ifa_addr)->sin_addr;uint32_t value=ntohl(ip.s_addr);
  if(!value||(value>>24)==127||(value>>16)==0xa9fe||(value>>24)>=224)continue;
  char buffer[INET_ADDRSTRLEN];if(inet_ntop(AF_INET,&ip,buffer,sizeof(buffer)))[addresses addObject:@(buffer)];
 }freeifaddrs(head);if(!addresses.count)return @{};
 NSArray *raw=IHKernelVPNStore([NSString stringWithFormat:@"State:/Network/Service/%@/DNS",service])[@"ServerAddresses"];
 NSMutableArray *servers=[NSMutableArray array];
 if([raw isKindOfClass:NSArray.class])for(id entry in raw){struct in_addr v4;struct in6_addr v6;
  if([entry isKindOfClass:NSString.class]&&(inet_pton(AF_INET,[entry UTF8String],&v4)==1||inet_pton(AF_INET6,[entry UTF8String],&v6)==1))[servers addObject:entry];}
 if(!servers.count)return @{};
 NSDictionary *global6=IHKernelVPNStore(@"State:/Network/Global/IPv6");
 NSDictionary *mapping6=IHKernelVPNStore([NSString stringWithFormat:@"State:/Network/Service/%@/IPv6",service]);
 BOOL usable6=ipv6.count&&[global6[@"PrimaryInterface"] isEqual:name]&&[global6[@"PrimaryService"] isEqual:service]&&[mapping6[@"InterfaceName"] isEqual:name];
 return @{@"interface":name,@"interfaceIndex":@(index),@"serviceID":service,
          @"ipv4addresses":[addresses sortedArrayUsingSelector:@selector(compare:)],@"dnsServers":[servers sortedArrayUsingSelector:@selector(compare:)],
          @"ipv6addresses":usable6?[ipv6 sortedArrayUsingSelector:@selector(compare:)]:@[]};
}
static BOOL IHKernelVPNMatches(NSDictionary *expected,NSDictionary *current) {
 if(!expected.count||!current.count)return NO;
 for(NSString *key in @[@"interface",@"interfaceIndex",@"serviceID",@"ipv4addresses",@"dnsServers"])
  if(![expected[key] isEqual:current[key]])return NO;
 return [(expected[@"ipv6addresses"]?:@[]) isEqual:(current[@"ipv6addresses"]?:@[])];
}
