#import <Foundation/Foundation.h>
#import "../src/common/IHVPNStartup.h"
#include <stdio.h>
#include <stdlib.h>

static unsigned checks;
static void check(BOOL result,const char *message){
 checks++;if(!result){fprintf(stderr,"FAIL: %s\n",message);exit(1);}
}
int main(void){@autoreleasepool{
 NSDictionary *attempt1=@{@"nonce":@"vpn",@"startupAttempt":@1};
 NSDictionary *attempt2=@{@"nonce":@"vpn",@"startupAttempt":@2};
 NSDictionary *replacement=@{@"nonce":@"replacement",@"startupAttempt":@1};
 NSDictionary *previous=@{@"nonce":@"vpn",@"startupAttempt":@1,@"heldRA":@[@41],
  @"vpnUpstreamPrepared":@YES,@"missingLegacySymbols":@[@"symbol"],
  @"nat44Committed":@YES,@"nat66Committed":@YES,@"raConfigurationReady":@YES,
  @"legacyPrefixCompatibility":@YES,@"lastIPv6BlockInterface":@"bridge100"};

 NSMutableDictionary *same=IHVPNStartupDiagnosticForAttempt(previous,attempt1,nil);
 check([same isEqual:previous],"same attempt retains its existing confirmations");
 same[@"raConfigurationReady"]=@NO;
 check([previous[@"raConfigurationReady"] isEqual:@YES],"candidate mutation cannot change the persisted snapshot");

 NSDictionary *rolled=IHVPNStartupDiagnosticForAttempt(previous,attempt2,nil);
 check([rolled[@"startupAttempt"] isEqual:@2],"retry diagnostic records the new attempt");
 check([rolled[@"heldRA"] isEqual:@[@41]],"retry preserves ownership of the previous attempt's suspended child");
 check([rolled[@"vpnUpstreamPrepared"] isEqual:@YES],"retry preserves session-scoped upstream preparation");
 check([rolled[@"missingLegacySymbols"] isEqual:@[@"symbol"]],"retry preserves process capabilities");
 check(!rolled[@"nat44Committed"]&&!rolled[@"nat66Committed"]&&!rolled[@"raConfigurationReady"],"retry clears every NAT and RA readiness confirmation");
 check(!rolled[@"legacyPrefixCompatibility"]&&!rolled[@"lastIPv6BlockInterface"],"retry clears attempt-specific bridge diagnostics");

 NSDictionary *appended=IHVPNStartupDiagnosticForAttempt(previous,attempt2,@42);
 check([appended[@"heldRA"] isEqual:@[@41,@42]],"first retry child is appended without losing the late previous child");
 check([IHVPNStartupDiagnosticForAttempt(appended,attempt2,@43)[@"heldRA"] isEqual:@[@41,@42,@43]],"subsequent children remain owned by the same session");
 check([IHVPNStartupDiagnosticForAttempt(appended,attempt2,@42)[@"heldRA"] isEqual:@[@41,@42]],"holding the same PID twice does not duplicate ownership");
 check([previous[@"heldRA"] isEqual:@[@41]],"appending a child cannot mutate the prior snapshot");

 NSDictionary *replaced=IHVPNStartupDiagnosticForAttempt(previous,replacement,@44);
 check([replaced[@"heldRA"] isEqual:@[@44]],"replacement session does not inherit suspended child ownership");
 check(!replaced[@"vpnUpstreamPrepared"]&&!replaced[@"nat44Committed"]&&!replaced[@"raConfigurationReady"],"replacement session inherits no upstream or configuration confirmation");
 check([replaced[@"missingLegacySymbols"] isEqual:@[@"symbol"]],"replacement retains process capabilities only");
 check([IHVPNStartupDiagnosticForAttempt(@{},attempt1,@45)[@"heldRA"] isEqual:@[@45]],"first child creates its session ownership record");

 NSMutableDictionary *persisted=IHVPNStartupDiagnosticForAttempt(@{},attempt1,nil);
 NSMutableDictionary *failedRA=IHVPNStartupDiagnosticForAttempt(persisted,attempt1,@46);failedRA[@"raConfigurationReady"]=@YES;
 __block unsigned writes=0;__block NSDictionary *written=nil;
 check(!IHVPNStartupPublishDiagnostic(persisted,failedRA,^BOOL(NSDictionary *value){(void)value;writes++;return NO;}),"failed RA persistence reports failure so its child is terminated");
 check(writes==1&&!persisted[@"raConfigurationReady"]&&![persisted[@"heldRA"] count],"failed RA publish retains the previous in-memory snapshot");
 NSMutableDictionary *nat=IHVPNStartupDiagnosticForAttempt(persisted,attempt1,nil);nat[@"nat66Committed"]=@YES;
 check(IHVPNStartupPublishDiagnostic(persisted,nat,^BOOL(NSDictionary *value){writes++;written=[value copy];return YES;}),"NAT confirmation can publish after the failed RA write");
 check(writes==2&&[persisted isEqual:written],"successful publish commits the written snapshot in memory");
 check(!written[@"raConfigurationReady"]&&![written[@"heldRA"] containsObject:@46],"subsequent NAT write cannot resurrect readiness for the terminated child");
 check(!IHVPNStartupConfigured(written,@"vpn",1,YES),"failed RA publication keeps the IPv6 forwarding gate closed");

 printf("PASS: %u VPN hook diagnostic checks\n",checks);return 0;
}}
