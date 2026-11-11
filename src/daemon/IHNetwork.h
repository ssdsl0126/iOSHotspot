#import <Foundation/Foundation.h>
@interface IHNetwork : NSObject
@property(nonatomic, copy) void (^changed)(void);
@property(nonatomic, readonly) NSDictionary *snapshot;
@property(nonatomic, readonly) BOOL available;
@property(nonatomic, readonly) NSString *error;
- (instancetype)initForHotspotControl;
- (void)refresh;
- (BOOL)setHotspot:(BOOL)on error:(NSError **)error;
- (NSDictionary *)captureBaseline;
- (BOOL)restoreBaseline:(NSDictionary *)baseline error:(NSError **)error;
- (NSDictionary *)interfaceCounters;
- (NSInteger)batteryPercent;
@end
