#pragma once
#import "IHNativeVPNProtocol.h"
#import "IHUSBInterfaces.h"
#import "IHSharingState.h"
#import <SystemConfiguration/SystemConfiguration.h>
#include <stdatomic.h>

// 控制面只使用具名API及公开Darwin ABI；VPN使用系统NAT，Wi-Fi使用原生IPv6前缀共享。
static NSString *const IH16Backend=@"named-client-kernel-v1";
static NSString *const IH16Helper=@"ioshotspot-vpn16";
static NSString *const IH16ControlKey=@"State:/iOSHotspot/Named16Control";
static const char *IH16ReadyNotification="com.newbie.ioshotspot.legacy-ready";
static const char *IH16StartNotification="com.newbie.ioshotspot.legacy-start";

// USB接口由驱动身份确认，不按enN编号或普通NCM通道猜测。
static BOOL IH16USBPort(NSString *name){
 for(NSDictionary *item in IHUSBInterfaceInventory(nil)[@"interfaces"])
  if([item[@"role"] isEqual:@"deviceTethering"]&&[item[@"name"] isEqual:name]&&[item[@"ifindex"] unsignedIntValue]==if_nametoindex(name.UTF8String))return YES;
 return NO;
}
static BOOL IH16SharingStopped(void){
 NSDictionary *value=IHKernelVPNStore(@"com.apple.MobileInternetSharing");
 return IHSharingIsStopped(value);
}
static NSDictionary *IH16AllocateSubnets(void){
 struct ifaddrs *head=NULL;if(getifaddrs(&head))return nil;NSMutableArray *selected=[NSMutableArray new];
 for(unsigned subnet=64;subnet<192&&selected.count<2;subnet++){
  uint32_t candidate=0xc0a80000u|(subnet<<8);BOOL busy=NO;
  for(struct ifaddrs *p=head;p;p=p->ifa_next){if(!p->ifa_addr||!p->ifa_netmask||p->ifa_addr->sa_family!=AF_INET)continue;
   uint32_t address=ntohl(((struct sockaddr_in*)p->ifa_addr)->sin_addr.s_addr),mask=ntohl(((struct sockaddr_in*)p->ifa_netmask)->sin_addr.s_addr);
   uint32_t common=mask&0xffffff00u;if(common&&(candidate&common)==(address&common)){busy=YES;break;}
  }
  if(!busy)[selected addObject:@{@"address":[NSString stringWithFormat:@"192.168.%u.1",subnet],@"mask":@"255.255.255.0",@"start":[NSString stringWithFormat:@"192.168.%u.2",subnet],@"end":[NSString stringWithFormat:@"192.168.%u.254",subnet]}];
 }freeifaddrs(head);return selected.count==2?@{@"wifi":selected[0],@"usb":selected[1]}:nil;
}
static NSString *IH16BridgeTransportFromAddresses(NSDictionary *session,NSString *bridge,struct ifaddrs *head){
 // PF回调内不派生ifconfig进程；用本轮唯一分配的网关地址核对系统接口。
 NSString *transport=nil;
 for(struct ifaddrs *p=head;p;p=p->ifa_next){if(!p->ifa_addr||p->ifa_addr->sa_family!=AF_INET||strcmp(p->ifa_name,bridge.UTF8String))continue;
  char text[INET_ADDRSTRLEN];if(!inet_ntop(AF_INET,&((struct sockaddr_in*)p->ifa_addr)->sin_addr,text,sizeof(text)))continue;
  struct in_addr assigned={0};uint32_t observed=ntohl(((struct sockaddr_in*)p->ifa_addr)->sin_addr.s_addr);
  for(NSString *kind in @[@"wifi",@"usb"])if(inet_pton(AF_INET,[session[@"ipv4Subnets"][kind][@"address"] UTF8String],&assigned)==1&&(ntohl(assigned.s_addr)&0xffffff00u)==(observed&0xffffff00u)){transport=kind;break;}
  if(transport)break;
 }return transport;
}
static NSString *IH16BridgeTransport(NSDictionary *session,NSString *bridge){
 struct ifaddrs *head=NULL;if(getifaddrs(&head))return nil;NSString *transport=IH16BridgeTransportFromAddresses(session,bridge,head);freeifaddrs(head);return transport;
}
static NSString *IH16BridgePrefix(NSDictionary *session,NSString *bridge){
 NSString *transport=IH16BridgeTransport(session,bridge);return transport?(session[@"prefixes"][transport]?:session[@"prefix"]):nil;
}
static NSArray<NSString*> *IH16SessionBridges(NSDictionary *session){
 struct ifaddrs *head=NULL;if(getifaddrs(&head))return @[];NSMutableSet *names=[NSMutableSet new];
 for(struct ifaddrs *p=head;p;p=p->ifa_next)if(p->ifa_addr&&p->ifa_addr->sa_family==AF_INET&&strncmp(p->ifa_name,"bridge",6)==0&&IH16BridgeTransportFromAddresses(session,@(p->ifa_name),head))[names addObject:@(p->ifa_name)];
 freeifaddrs(head);return [[names allObjects] sortedArrayUsingSelector:@selector(compare:)];
}
static BOOL IH16HasIPv6Address(NSString *name,NSString *text){
 struct in6_addr address={0};if(inet_pton(AF_INET6,text.UTF8String,&address)!=1)return NO;struct ifaddrs *head=NULL;if(getifaddrs(&head))return NO;BOOL found=NO;
 for(struct ifaddrs *p=head;p;p=p->ifa_next)if(p->ifa_addr&&p->ifa_addr->sa_family==AF_INET6&&!strcmp(p->ifa_name,name.UTF8String)&&!memcmp(&((struct sockaddr_in6*)p->ifa_addr)->sin6_addr,&address,sizeof(address))){found=YES;break;}
 freeifaddrs(head);return found;
}

static BOOL IH16Process(pid_t pid){return IHNativeProcess(pid,IH16Helper.UTF8String);}
static BOOL IH16IdentityMatches(NSDictionary *expected){
 NSString *name=expected[@"interface"],*service=expected[@"serviceID"];
 if(!IHKernelVPNName(name)||!if_nametoindex(name.UTF8String)||if_nametoindex(name.UTF8String)!=[expected[@"interfaceIndex"] unsignedIntValue])return NO;
 for(NSString *entity in @[@"IPv4",@"IPv6",@"DNS"]){
  NSDictionary *value=IHKernelVPNStore([NSString stringWithFormat:@"State:/Network/Service/%@/%@",service,entity]);
  NSString *field=[entity isEqual:@"DNS"]?@"ServerAddresses":@"Addresses",*reference=[entity isEqual:@"DNS"]?@"dnsServers":[entity isEqual:@"IPv4"]?@"ipv4addresses":@"ipv6addresses";
  if(![entity isEqual:@"DNS"]&&![value[@"InterfaceName"] isEqual:name])return NO;
  if(![[value[field] sortedArrayUsingSelector:@selector(compare:)] isEqual:expected[reference]])return NO;
 }
 NSMutableArray *v4=[NSMutableArray new],*v6=[NSMutableArray new];struct ifaddrs *head=NULL;if(getifaddrs(&head))return NO;
 for(struct ifaddrs *p=head;p;p=p->ifa_next){
  if(!p->ifa_addr||strcmp(p->ifa_name,name.UTF8String)||(p->ifa_flags&(IFF_UP|IFF_RUNNING|IFF_POINTOPOINT))!=(IFF_UP|IFF_RUNNING|IFF_POINTOPOINT))continue;
  char buffer[INET6_ADDRSTRLEN];if(p->ifa_addr->sa_family==AF_INET&&inet_ntop(AF_INET,&((struct sockaddr_in*)p->ifa_addr)->sin_addr,buffer,sizeof(buffer)))[v4 addObject:@(buffer)];
  if(p->ifa_addr->sa_family==AF_INET6){struct in6_addr *ip=&((struct sockaddr_in6*)p->ifa_addr)->sin6_addr;
   if(!IN6_IS_ADDR_UNSPECIFIED(ip)&&!IN6_IS_ADDR_LOOPBACK(ip)&&!IN6_IS_ADDR_LINKLOCAL(ip)&&!IN6_IS_ADDR_MULTICAST(ip)&&inet_ntop(AF_INET6,ip,buffer,sizeof(buffer)))[v6 addObject:@(buffer)];}
 }freeifaddrs(head);
 return [[v4 sortedArrayUsingSelector:@selector(compare:)] isEqual:expected[@"ipv4addresses"]]&&[[v6 sortedArrayUsingSelector:@selector(compare:)] isEqual:expected[@"ipv6addresses"]];
}
static BOOL IH16RoutesMatch(NSDictionary *binding){return IHKernelRoutesMatch([binding[@"interfaceIndex"] unsignedIntValue],[binding[@"ipv6addresses"] count]>0);}
static NSDictionary *IH16ActiveSession(void){
 NSDictionary *session=IHNativeReadJSON(IHNativeSessionPath),*state=IHNativeReadJSON(IHNativeStatePath),*runtime=IHNativeReadJSON(IHSourceRuntimePath);
 if(![session[@"backend"] isEqual:IH16Backend]||![runtime[@"enabled"] boolValue]||![runtime[@"source"] isEqual:@"vpn"]||![runtime[@"kernelBackendVersion"] isEqual:@4])return nil;
 if(![runtime[@"nativeSession"] isEqual:session[@"nonce"]]||![state[@"nonce"] isEqual:session[@"nonce"]]||![state[@"radioReady"] boolValue])return nil;
 if(IHNativeIPv6Enabled(runtime)!=IHNativeIPv6Enabled(session))return nil;
 if(!IHNativeProcess([session[@"parentPID"] intValue],"ioshotspotd")||!IH16Process([state[@"pid"] intValue])||[state[@"parentPID"] intValue]!=[session[@"parentPID"] intValue])return nil;
 NSString *name=session[@"binding"][@"interface"];if(!IHKernelVPNName(name)||if_nametoindex(name.UTF8String)!=[session[@"binding"][@"interfaceIndex"] unsignedIntValue])return nil;
 return session;
}
