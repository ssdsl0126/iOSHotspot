#import <Foundation/Foundation.h>

@interface IHVPNConnector : NSObject
@property(nonatomic, readonly) BOOL supported;
@property(nonatomic, readonly) BOOL busy;
@property(nonatomic, readonly) NSDictionary *state;
- (BOOL)connectWithCompletion:(void (^)(NSDictionary *result))completion;
- (void)cancel;
- (void)recordFailure:(NSString *)message;
@end
