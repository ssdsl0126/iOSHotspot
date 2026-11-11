#import <Foundation/Foundation.h>
@interface IHNativeVPN:NSObject
@property(nonatomic,readonly) BOOL supported;
@property(nonatomic,readonly) NSDictionary *capabilities;
@property(nonatomic,readonly) BOOL running;
@property(nonatomic,readonly) BOOL busy;
@property(nonatomic,readonly) NSString *nonce;
@property(nonatomic,readonly) NSDictionary *state;
@property(nonatomic,copy) void (^changed)(void);
- (BOOL)prepare:(NSDictionary*)binding ipv6:(BOOL)ipv6 error:(NSError**)error;
- (BOOL)start:(NSError**)error;
- (BOOL)stop:(NSError**)error;
- (BOOL)requestStop:(NSError**)error;
- (BOOL)recover:(NSError**)error;
@end
