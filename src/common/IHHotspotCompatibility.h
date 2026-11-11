#import <Foundation/Foundation.h>

// 独立控制系统原生兼容性选项，不参与转发、来源选择或会话管理。
@interface IHHotspotCompatibility : NSObject
+ (instancetype)shared;
- (NSDictionary *)state;
- (NSDictionary *)setEnabled:(BOOL)enabled error:(NSError **)error;
@end
