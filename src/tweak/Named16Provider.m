#import <Foundation/Foundation.h>
#import "../common/IHPaths.h"
#import <NetworkExtension/NetworkExtension.h>
#include <objc/runtime.h>
#include <net/if.h>
#include <dlfcn.h>

static void(*originalSettings)(id,SEL,NEPacketTunnelNetworkSettings*,void(^)(NSError*));
// 提供者只读configd中的临时控制实体；真机已核实VPN沙箱可读但无写权限。
static NSDictionary *readControl(void){
 typedef CFPropertyListRef(*CopyValue)(CFTypeRef,CFStringRef);static CopyValue copy;static dispatch_once_t once;
 dispatch_once(&once,^{copy=dlsym(RTLD_DEFAULT,"SCDynamicStoreCopyValue");});
 id value=copy?CFBridgingRelease(copy(NULL,CFSTR("State:/iOSHotspot/Named16Control"))):nil;
 return [value isKindOfClass:NSDictionary.class]&&[value[@"version"] isEqual:@1]&&[value[@"active"] boolValue]&&[value[@"backend"] isEqual:@"named-client-kernel-v1"]?value:nil;
}
static BOOL isDefault(NEIPv6Route *route){return [route.destinationAddress isEqual:@"::"]&&route.destinationNetworkPrefixLength.integerValue==0;}
static void setSettings(id self,SEL selector,NEPacketTunnelNetworkSettings *settings,void(^completion)(NSError*)){
 @autoreleasepool{
  NEIPv6Settings *v6=settings.IPv6Settings;BOOL excluded=NO;for(NEIPv6Route *route in v6.excludedRoutes)if(isDefault(route))excluded=YES;
  if(v6&&excluded){NSDictionary *control=readControl();NSArray *addresses=control[@"addresses"],*prefixes=control[@"prefixes"];NSString *interface=control[@"interface"];
   if([addresses isKindOfClass:NSArray.class]&&addresses.count&&[prefixes isKindOfClass:NSArray.class]&&prefixes.count==addresses.count&&[interface isKindOfClass:NSString.class]&&if_nametoindex(interface.UTF8String)==[control[@"interfaceIndex"] unsignedIntValue]&&[[v6.addresses sortedArrayUsingSelector:@selector(compare:)] isEqual:[addresses sortedArrayUsingSelector:@selector(compare:)]]){
    BOOL valid=YES;for(id number in prefixes)if(![number isKindOfClass:NSNumber.class]||[number integerValue]<1||[number integerValue]>128)valid=NO;
    if(valid){
     NEPacketTunnelNetworkSettings *copy=[settings copy];NEIPv6Settings *replacement=[[NEIPv6Settings alloc]initWithAddresses:addresses networkPrefixLengths:prefixes];
     NSMutableArray *included=[v6.includedRoutes mutableCopy]?:[NSMutableArray new],*excludes=[v6.excludedRoutes mutableCopy]?:[NSMutableArray new];
     BOOL hasDefault=NO;for(NEIPv6Route *route in included)if(isDefault(route))hasDefault=YES;if(!hasDefault)[included addObject:NEIPv6Route.defaultRoute];
     for(NSInteger i=(NSInteger)excludes.count-1;i>=0;i--)if(isDefault(excludes[(NSUInteger)i]))[excludes removeObjectAtIndex:(NSUInteger)i];
     replacement.includedRoutes=included;replacement.excludedRoutes=excludes;copy.IPv6Settings=replacement;
     originalSettings(self,selector,copy,completion);return;
    }
   }
  }
  originalSettings(self,selector,settings,completion);
 }
}
__attribute__((constructor))static void install(void){@autoreleasepool{
 NSDictionary *extension=NSBundle.mainBundle.infoDictionary[@"NSExtension"];
 if(![extension[@"NSExtensionPointIdentifier"] isEqual:@"com.apple.networkextension.packet-tunnel"])return;
 Class provider=NSClassFromString(@"NEPacketTunnelProvider");SEL selector=@selector(setTunnelNetworkSettings:completionHandler:);if(!provider||!class_getInstanceMethod(provider,selector))return;
 void(*hook)(Class,SEL,IMP,IMP*)=dlsym(RTLD_DEFAULT,"MSHookMessageEx");if(!hook){void *library=dlopen(IHJailbreakPath(@"/usr/lib/libsubstrate.dylib").fileSystemRepresentation,RTLD_NOW);if(library)hook=dlsym(library,"MSHookMessageEx");}
 if(hook)hook(provider,selector,(IMP)setSettings,(IMP*)&originalSettings);
}}
