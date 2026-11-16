#import <Foundation/Foundation.h>
#import "../src/common/IHVPNStartup.h"
#import "../src/common/IHNativeVPNProtocol.h"
#import "../src/common/IHSharingState.h"
#include <stdio.h>
#include <stdlib.h>

static unsigned checks;
static void check(BOOL result,const char *message){
 checks++;if(!result){fprintf(stderr,"FAIL: %s\n",message);exit(1);}
}
int main(void){@autoreleasepool{
 NSString *nonce=@"current-vpn";
 NSDictionary *ready=@{@"nonce":nonce,@"startupAttempt":@1,@"nat66Committed":@YES,@"raConfigurationReady":@YES};
 check(IHVPNStartupConfigured(ready,nonce,1,YES),"same-attempt IPv6 NAT and RA confirmation accepted");
 check(!IHVPNStartupConfigured(ready,nonce,2,YES),"restarted radio cannot reuse previous NAT/RA confirmation");
 check(!IHVPNStartupConfigured(ready,@"replacement-vpn",1,YES),"previous VPN cannot authorize current VPN");
 check(!IHVPNStartupConfigured(@{@"nonce":nonce,@"nat66Committed":@YES,@"raConfigurationReady":@YES},nonce,1,YES),"untagged legacy confirmation is rejected");
 check(!IHVPNStartupConfigured(@{@"nonce":nonce,@"startupAttempt":@1,@"nat66Committed":@YES},nonce,1,YES),"NAT66 alone cannot open the IPv6 gate");
 check(!IHVPNStartupConfigured(@{@"nonce":nonce,@"startupAttempt":@1,@"raConfigurationReady":@YES},nonce,1,YES),"RA alone cannot open the IPv6 gate");
 check(IHVPNStartupConfigured(@{@"nonce":nonce,@"startupAttempt":@2,@"nat44Committed":@YES},nonce,2,NO),"IPv4 requires its own NAT44 confirmation without RA");
 check(!IHVPNStartupConfigured(ready,nonce,1,NO),"NAT66 does not authorize IPv4-only sharing");

 NSDictionary *prepared=@{@"nonce":nonce,@"vpnUpstreamPrepared":@YES};
 NSDictionary *rejected=@{@"sessionNonce":nonce,@"time":@110,@"apiResult":@"vpnNamed16AuthorizationRejected"};
 check([IHVPNStartupRestartReason(prepared,@[],nonce,100,0,NO,YES) isEqual:@"vpnUpstreamPrepared"],"upstream confirmation enters the full radio restart path");
 check(!IHVPNStartupRestartReason(prepared,@[],nonce,100,0,NO,NO),"unstable VPN cannot restart radio");
 check(!IHVPNStartupRestartReason(prepared,@[],nonce,100,1,YES,YES),"upstream preparation causes at most one restart");
 check(!IHVPNStartupRestartReason(prepared,@[],@"other-vpn",100,0,NO,YES),"stale upstream confirmation cannot restart radio");
 check([IHVPNStartupRestartReason(@{},@[@{},rejected],nonce,100,0,NO,YES) isEqual:@"sourceAuthorizationRejected"],"USB rejection is eligible even without a Wi-Fi rejection");
 check(!IHVPNStartupRestartReason(@{},@[rejected],nonce,111,0,NO,YES),"source rejection before latest request cannot restart again");
 check(!IHVPNStartupRestartReason(prepared,@[rejected],nonce,100,2,NO,YES),"both restart reasons share the two-retry limit");
 check(!IHVPNStartupRestartReason(@{},@[@{@"sessionNonce":nonce,@"time":@110,@"apiResult":@"rejected"}],nonce,100,0,NO,YES),"unknown native rejection is not retried");

 double since=0;
 check(!IHVPNStartupSettled(&since,10,YES),"first ready sample does not immediately authorize retry");
 check(!IHVPNStartupSettled(&since,10.2,YES),"brief readiness is not stable");
 check(!IHVPNStartupSettled(&since,10.25,NO),"route mismatch clears stability interval");
 check(!IHVPNStartupSettled(&since,10.4,YES),"readiness after a mismatch starts a fresh interval");
 check(IHVPNStartupSettled(&since,10.8,YES),"continuous readiness can authorize retry");

 NSDictionary *session=@{@"nonce":nonce,@"binding":@{@"interface":@"utun5"}};
 NSDictionary *attempt1=@{@"nonce":nonce,@"startupAttempts":@1},*attempt2=@{@"nonce":nonce,@"startupAttempts":@2};
 NSDictionary *captured=IHNativeSessionWithStartupAttempt(session,attempt1);
 check(IHNativeStartupAttemptMatches(captured,attempt1),"callback retains its original startup attempt");
 check(!IHNativeStartupAttemptMatches(captured,attempt2),"late PF/RA callback is rejected after radio restart");
 check(!IHNativeStartupAttemptMatches(captured,@{@"nonce":@"new-vpn",@"startupAttempts":@1}),"late callback is rejected after VPN replacement");
 check(!IHNativeSessionWithStartupAttempt(session,@{@"nonce":nonce}),"missing attempt does not create authorized callback context");
 check(!session[@"startupAttempt"],"capturing callback context does not mutate original authorization");

 NSDictionary *binding=@{@"interface":@"utun5",@"interfaceIndex":@5,@"serviceID":@"vpn-service",@"ipv4addresses":@[@"10.0.0.2"],@"ipv6addresses":@[@"fd00::2"],@"dnsServers":@[@"1.1.1.1"]};
 NSDictionary *authorizedSession=@{@"nonce":nonce,@"vpnIPv6":@YES,@"binding":binding};
 NSMutableDictionary *authorization=[@{@"enabled":@YES,@"source":@"vpn",@"nativeSession":nonce,@"allowLegacyStart":@YES,@"vpnIPv6":@YES,@"vpnBinding":binding} mutableCopy];
 check(IHNativeSessionAuthorizationMatches(authorizedSession,authorization),"current session and binding authorize startup and resume");
 authorization[@"allowLegacyStart"]=@NO;
 check(!IHNativeSessionAuthorizationMatches(authorizedSession,authorization),"stop revokes startup and resume while nonce is retained for cleanup");
 authorization[@"allowLegacyStart"]=@YES;authorization[@"vpnBinding"]=@{};
 check(!IHNativeSessionAuthorizationMatches(authorizedSession,authorization),"empty binding revokes a paused child's authority before SIGTERM delivery");
 authorization[@"vpnBinding"]=binding;authorization[@"nativeSession"]=@"replacement";
 check(!IHNativeSessionAuthorizationMatches(authorizedSession,authorization),"a replacement nonce cannot authorize the old helper");
 authorization[@"nativeSession"]=nonce;authorization[@"vpnIPv6"]=@NO;
 check(!IHNativeSessionAuthorizationMatches(authorizedSession,authorization),"runtime family mode must match session authorization");
 authorization[@"vpnIPv6"]=@YES;authorization[@"enabled"]=@NO;
 check(!IHNativeSessionAuthorizationMatches(authorizedSession,authorization),"disabled runtime never authorizes resume");
 authorization[@"enabled"]=@YES;NSMutableDictionary *rebound=[binding mutableCopy];rebound[@"interfaceIndex"]=@6;authorization[@"vpnBinding"]=rebound;
 check(!IHNativeSessionAuthorizationMatches(authorizedSession,authorization),"current nonce cannot authorize a different tunnel binding");
 check(!IHNativeSessionAuthorizationMatches(authorizedSession,@{}),"missing runtime fails closed");
 check(!IHNativeSessionAuthorizationMatches(authorizedSession,@{@"vpnBinding":@[]}),"invalid binding type fails closed");

 NSDictionary *failedRadio=@{@"State":@1023,@"UState":@1023,@"Hosts":@{@"Current":@0},@"InternalInterfaces":@[],@"ExternalInterfaces":@[]};
 check(!IHSharingUnavailableWithoutBridge(failedRadio,NULL),"reported requested-on empty radio is not a stopped service");
 check(!IHSharingIsStopped(failedRadio),"blank bridge cannot authorize restoration while system remains on");
 check(IHSharingIsStopped(@{@"State":@1022,@"UState":@1022,@"InternalInterfaces":@[]}),"explicit system stop permits recovery");
 check(!IHSharingIsStopped(@{}),"missing system snapshot cannot authorize recovery");
 NSDictionary *unavailableRequested=@{@"State":@1020,@"UState":@1023,@"Hosts":@{@"Current":@0},@"InternalInterfaces":@[],@"ExternalInterfaces":@[]};
 check(IHSharingUnavailableWithoutBridge(unavailableRequested,NULL),"unavailable empty system can have no active sharing while requested on");
 check(!IHSharingHasStoppedRequest(unavailableRequested),"VPN restart still requires withdrawal of unavailable desired-on state");
 check(IHSharingHasStoppedRequest(@{@"UState":@1022,@"InternalInterfaces":@[]}),"withdrawn off request permits VPN cleanup");
 printf("PASS: %u VPN startup and recovery checks\n",checks);return 0;
}}
