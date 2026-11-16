#pragma once
#import <Foundation/Foundation.h>

// 配置发布需要连续稳定一小段时间；任何一次失配都会重新计时。
static inline BOOL IHVPNStartupSettled(double *since,double now,BOOL ready) {
 if(!ready){*since=0;return NO;}
 if(*since<=0)*since=now;
 return now-*since>=0.3;
}

// 仅重试本轮明确被来源模块拒绝的初始化，不重试旧会话或未知失败。
static inline BOOL IHVPNStartupRetryAllowed(NSDictionary *diagnostic,NSString *nonce,NSTimeInterval requestedAt,NSUInteger retries) {
 return retries<2&&nonce.length&&[diagnostic[@"sessionNonce"] isEqual:nonce]&&
  [diagnostic[@"time"] isKindOfClass:NSNumber.class]&&[diagnostic[@"time"] doubleValue]>0&&
  [diagnostic[@"time"] doubleValue]>=requestedAt&&
  [@[@"legacySessionNotReady",@"vpnNamed16AuthorizationRejected",@"vpnIPv4AuthorizationRejected"] containsObject:diagnostic[@"apiResult"]?:@""];
}

// 准备确认只允许当前nonce的一次重发，不能代替NAT、网桥或转发校验。
static inline BOOL IHVPNUpstreamRetryAllowed(NSDictionary *diagnostic,NSString *nonce,BOOL retried) {
 return !retried&&nonce.length&&[diagnostic[@"nonce"] isEqual:nonce]&&[diagnostic[@"vpnUpstreamPrepared"] isEqual:@YES];
}

// 同一nonce的无线重建也必须取得新一轮PF及RA确认，不能复用上轮成功位。
static inline BOOL IHVPNStartupConfigured(NSDictionary *diagnostic,NSString *nonce,NSUInteger attempt,BOOL ipv6) {
 return nonce.length&&attempt>0&&[diagnostic[@"nonce"] isEqual:nonce]&&
  [diagnostic[@"startupAttempt"] unsignedIntegerValue]==attempt&&
  [diagnostic[ipv6?@"nat66Committed":@"nat44Committed"] isEqual:@YES]&&
  (!ipv6||[diagnostic[@"raConfigurationReady"] isEqual:@YES]);
}

// 挂起进程属于整个会话；重试只清除本次配置确认，不能丢失仍需释放的PID。
// 返回独立快照，写入失败时调用方可以保留之前已持久化的诊断。
static inline NSMutableDictionary *IHVPNStartupDiagnosticForAttempt(NSDictionary *previous,NSDictionary *session,NSNumber *heldRAPID) {
 BOOL sameNonce=[previous[@"nonce"] isEqual:session[@"nonce"]];
 BOOL sameAttempt=sameNonce&&[previous[@"startupAttempt"] isEqual:session[@"startupAttempt"]];
 NSMutableDictionary *current=sameAttempt?[previous mutableCopy]:[NSMutableDictionary new];
 if(!sameAttempt){
  current[@"nonce"]=session[@"nonce"];current[@"startupAttempt"]=session[@"startupAttempt"];
  current[@"heldRA"]=sameNonce?(previous[@"heldRA"]?:@[]):@[];
  if(sameNonce&&previous[@"vpnUpstreamPrepared"])current[@"vpnUpstreamPrepared"]=previous[@"vpnUpstreamPrepared"];
  if(previous[@"missingLegacySymbols"])current[@"missingLegacySymbols"]=previous[@"missingLegacySymbols"];
 }
 if(heldRAPID){
  NSMutableArray *pids=[(current[@"heldRA"]?:@[]) mutableCopy];
  if(![pids containsObject:heldRAPID])[pids addObject:heldRAPID];
  current[@"heldRA"]=pids;
 }
 return current;
}

// 内存只保留已成功发布的快照，失败的RA确认不能在之后的NAT写入中复活。
static inline BOOL IHVPNStartupPublishDiagnostic(NSMutableDictionary *diagnostic,NSDictionary *candidate,BOOL (^writer)(NSDictionary *)) {
 if(!writer(candidate))return NO;
 [diagnostic setDictionary:candidate];return YES;
}

// 两类确认都进入关闭→稳定→开启；准备确认本身从不放行流量。
static inline NSString *IHVPNStartupRestartReason(NSDictionary *misd,NSArray<NSDictionary*> *sources,NSString *nonce,
 NSTimeInterval requestedAt,NSUInteger retries,BOOL upstreamRetried,BOOL settled) {
 if(!settled||retries>=2)return nil;
 if(IHVPNUpstreamRetryAllowed(misd,nonce,upstreamRetried))return @"vpnUpstreamPrepared";
 for(NSDictionary *source in sources)if(IHVPNStartupRetryAllowed(source,nonce,requestedAt,retries))return @"sourceAuthorizationRejected";
 return nil;
}
