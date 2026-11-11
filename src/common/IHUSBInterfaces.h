#import <Foundation/Foundation.h>
#import <SystemConfiguration/SystemConfiguration.h>
#include <dlfcn.h>
#include <net/if.h>
#include <ifaddrs.h>

// 只读发现USB接口。编号不是身份；方向与用途必须由IORegistry驱动链确认。
static inline NSDictionary *IHUSBInterfaceInventory(NSString *targetUDID) {
    void *library=dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",RTLD_NOW|RTLD_LOCAL);
    CFMutableDictionaryRef (*matching)(const char *)=library?dlsym(library,"IOServiceMatching"):NULL;
    int (*getServices)(unsigned int,CFDictionaryRef,unsigned int *)=library?dlsym(library,"IOServiceGetMatchingServices"):NULL;
    unsigned int (*next)(unsigned int)=library?dlsym(library,"IOIteratorNext"):NULL;
    int (*release)(unsigned int)=library?dlsym(library,"IOObjectRelease"):NULL;
    int (*parent)(unsigned int,const char *,unsigned int *)=library?dlsym(library,"IORegistryEntryGetParentEntry"):NULL;
    bool (*conforms)(unsigned int,const char *)=library?dlsym(library,"IOObjectConformsTo"):NULL;
    CFTypeRef (*property)(unsigned int,CFStringRef,CFAllocatorRef,unsigned int)=library?dlsym(library,"IORegistryEntryCreateCFProperty"):NULL;
    int (*entryID)(unsigned int,uint64_t *)=library?dlsym(library,"IORegistryEntryGetRegistryEntryID"):NULL;
    CFPropertyListRef (*copyState)(SCDynamicStoreRef,CFStringRef)=dlsym(RTLD_DEFAULT,"SCDynamicStoreCopyValue");
    if(!matching||!getServices||!next||!release||!parent||!conforms||!property||!entryID){
        if(library)dlclose(library);
        return @{@"ok":@NO,@"error":@"USB只读发现API不可用",@"interfaces":@[]};
    }
    NSString *(^normalize)(NSString *)=^NSString *(NSString *value){
        if(![value isKindOfClass:NSString.class])return @"";
        return [[value stringByReplacingOccurrencesOfString:@"-" withString:@""] lowercaseString];
    };
    NSString *expected=normalize(targetUDID);
    unsigned int iterator=0;int status=getServices(0,matching("IOEthernetInterface"),&iterator);
    if(status||!iterator){dlclose(library);return @{@"ok":@NO,@"error":@"USB接口枚举失败",@"interfaces":@[]};}
    NSMutableArray *result=[NSMutableArray array];unsigned int interface=0;
    while((interface=next(iterator))){
        id rawName=CFBridgingRelease(property(interface,CFSTR("BSD Name"),kCFAllocatorDefault,0));
        if(![rawName isKindOfClass:NSString.class]||![rawName length]||[rawName length]>=IFNAMSIZ){release(interface);continue;}
        NSString *name=rawName,*role=nil;BOOL targetMatches=expected.length==0;
        unsigned int node=interface;
        for(NSUInteger depth=0;depth<24;depth++){
            // 私有/受限NCM绝不能按普通USB热点处理。
            if(conforms(node,"AppleUSBDeviceNCMPrivateEthernetInterface"))role=@"devicePrivateNCM";
            else if(conforms(node,"AppleUSBHostNCMRestrictedEthernetInterface"))role=@"hostRestrictedNCM";
            else if(!role&&conforms(node,"AppleUSBEthernetDevice"))role=@"deviceTethering";
            else if(!role&&conforms(node,"AppleUSBEthernetHost"))role=@"hostTethering";
            else if(!role&&conforms(node,"AppleUSBDeviceNCMData"))role=@"deviceNCM";
            else if(!role&&conforms(node,"AppleUSBNCMData"))role=@"hostNCM";
            if(expected.length){
                id serial=CFBridgingRelease(property(node,CFSTR("USB Serial Number"),kCFAllocatorDefault,0));
                if([normalize(serial) isEqual:expected])targetMatches=YES;
            }
            unsigned int ancestor=0;int found=parent(node,"IOService",&ancestor);
            if(node!=interface)release(node);
            if(found||!ancestor)break;
            node=ancestor;
            if(depth==23)release(node);
        }
        if(role&&targetMatches){
            uint64_t identity=0;entryID(interface,&identity);
            NSString *key=[NSString stringWithFormat:@"State:/Network/Interface/%@/Link",name];
            id link=copyState?CFBridgingRelease(copyState(NULL,(__bridge CFStringRef)key)):nil;
            id active=[link isKindOfClass:NSDictionary.class]?link[@"Active"]:nil;
            // 未发布链路状态时保持unknown，不把IFF_RUNNING误判为有客户端。
            NSMutableDictionary *item=[@{@"name":name,@"role":role,@"ifindex":@(if_nametoindex(name.UTF8String)),@"registryID":@(identity),@"linkActive":active?:NSNull.null} mutableCopy];
            struct ifaddrs *head=NULL;
            if(getifaddrs(&head)==0){for(struct ifaddrs *p=head;p;p=p->ifa_next)if(!strcmp(p->ifa_name,name.UTF8String)){item[@"up"]=@((p->ifa_flags&IFF_UP)!=0);break;}freeifaddrs(head);}
            [result addObject:item];
        }
        release(interface);
    }
    release(iterator);dlclose(library);
    return @{@"ok":@YES,@"networkMutation":@NO,@"targetFiltered":@(expected.length>0),@"interfaces":result};
}
