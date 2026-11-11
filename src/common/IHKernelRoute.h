#pragma once
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <stdatomic.h>
#include <sys/sysctl.h>

// Darwin稳定路由消息ABI；iOS公开SDK未携带net/route.h。只发送RTM_GET，不发送增删改消息。
typedef struct {
 uint16_t length;uint8_t version,type;uint16_t index;
 int32_t flags,addresses,pid,sequence,error,use;uint32_t initializers,metrics[14];
} IHRouteMessage;
_Static_assert(sizeof(IHRouteMessage)==92,"Darwin路由消息布局不符");
static unsigned IHKernelRouteIndex(int family,const char *destination){
 static _Atomic int32_t sequence=700000;
 int fd=socket(PF_ROUTE,SOCK_RAW,0);if(fd<0)return 0;unsigned result=0;
 struct timeval timeout={0,200000};
 if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))){close(fd);return 0;}
 struct {IHRouteMessage header;struct sockaddr_in6 destination;} query={0};
 size_t addressSize=family==AF_INET?sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6);
 query.header.length=(uint16_t)(sizeof(IHRouteMessage)+addressSize);query.header.version=5;query.header.type=4;
 query.header.addresses=1;query.header.pid=getpid();query.header.sequence=atomic_fetch_add(&sequence,1);
 struct sockaddr *address=(struct sockaddr*)&query.destination;address->sa_len=(uint8_t)addressSize;address->sa_family=(sa_family_t)family;
 void *bytes=family==AF_INET?(void*)&((struct sockaddr_in*)address)->sin_addr:(void*)&query.destination.sin6_addr;
 if(inet_pton(family,destination,bytes)!=1||write(fd,&query,query.header.length)!=query.header.length){close(fd);return 0;}
 unsigned char buffer[4096];
 for(unsigned attempt=0;attempt<8;attempt++){
  ssize_t count=read(fd,buffer,sizeof(buffer));if(count<(ssize_t)sizeof(IHRouteMessage))break;
  IHRouteMessage response;memcpy(&response,buffer,sizeof(response));
  if(response.version!=5||response.type!=4||response.pid!=getpid()||response.sequence!=query.header.sequence)continue;
  if(response.length<=count&&!response.error&&(response.flags&1)&&!(response.flags&0x1008))result=response.index;break;
 }
 close(fd);return result;
}
static BOOL IHKernelRoutesMatch(unsigned index,BOOL ipv6){
 return index&&IHKernelRouteIndex(AF_INET,"1.1.1.1")==index&&IHKernelRouteIndex(AF_INET,"200.1.1.1")==index&&
  (!ipv6||IHKernelRouteIndex(AF_INET6,"2600:1901:0:13e0::")==index);
}
static int IHKernelForwarding(int family){
 int value=-1;size_t size=sizeof(value);
 return sysctlbyname(family==AF_INET?"net.inet.ip.forwarding":"net.inet6.ip6.forwarding",&value,&size,NULL,0)==0?value:-1;
}
