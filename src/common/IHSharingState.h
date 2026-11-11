#pragma once
#import <Foundation/Foundation.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <string.h>

// 不可用状态中的开启意图不代表服务仍存活；同时核实SC和公开内核接口。
static inline BOOL IHSharingUnavailableWithoutBridge(NSDictionary *sharing,struct ifaddrs *head) {
    if(![sharing[@"State"] isKindOfClass:NSNumber.class]||
       ![@[@1020,@1021] containsObject:sharing[@"State"]]||
       ![sharing[@"UState"] isKindOfClass:NSNumber.class]||
       ![@[@1022,@1023] containsObject:sharing[@"UState"]]||
       ![sharing[@"Hosts"] isKindOfClass:NSDictionary.class]||
       ![sharing[@"Hosts"][@"Current"] isKindOfClass:NSNumber.class]||
       [sharing[@"Hosts"][@"Current"] integerValue]!=0)return NO;
    for(NSString *key in @[@"InternalInterfaces",@"ExternalInterfaces"])
        if(![sharing[key] isKindOfClass:NSArray.class]||[sharing[key] count])return NO;
    for(struct ifaddrs *p=head;p;p=p->ifa_next){
        if(!p->ifa_name||!p->ifa_addr||strncmp(p->ifa_name,"bridge",6)||
           p->ifa_addr->sa_family!=AF_INET||
           (p->ifa_flags&(IFF_UP|IFF_RUNNING))!=(IFF_UP|IFF_RUNNING))continue;
        uint32_t address=ntohl(((struct sockaddr_in*)p->ifa_addr)->sin_addr.s_addr);
        if(address&&(address>>16)!=0xa9fe)return NO;
    }
    return YES;
}
static inline BOOL IHSharingIsUnavailableEmpty(NSDictionary *sharing) {
    struct ifaddrs *head=NULL;if(getifaddrs(&head))return NO;
    BOOL stopped=IHSharingUnavailableWithoutBridge(sharing,head);freeifaddrs(head);return stopped;
}
// 缺失、未知或仍有服务的状态不视为清理完成。
static inline BOOL IHSharingIsStopped(NSDictionary *sharing) {
    return ([sharing[@"UState"] isKindOfClass:NSNumber.class]&&
        [sharing[@"UState"] intValue]==1022&&
        [sharing[@"InternalInterfaces"] isKindOfClass:NSArray.class]&&
        [sharing[@"InternalInterfaces"] count]==0)||IHSharingIsUnavailableEmpty(sharing);
}
