#pragma once
#import <Foundation/Foundation.h>
// 系统原生单元格类型枚举值，不涉及对象布局或设备偏移。
typedef NS_ENUM(NSInteger, PSCellType) {
    PSTitleValueCell = 4,
    PSSwitchCell = 6,
    PSButtonCell = 13
};
@interface PSSpecifier : NSObject
@property(nonatomic) SEL buttonAction;
+ (instancetype)groupSpecifierWithName:(NSString *)name;
+ (instancetype)preferenceSpecifierNamed:(NSString *)name target:(id)target set:(SEL)set get:(SEL)get detail:(Class)detail cell:(PSCellType)cell edit:(Class)edit;
- (void)setProperty:(id)value forKey:(NSString *)key;
@end
