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
