#pragma once
#import <UIKit/UIKit.h>
// 仅声明项目使用的系统方法；实际实现由控制中心宿主中的系统框架提供。
@interface CCUIToggleModule : NSObject
@property(nonatomic, getter=isSelected) BOOL selected;
@property(nonatomic, readonly) UIImage *iconGlyph;
@property(nonatomic, readonly) UIImage *selectedIconGlyph;
@property(nonatomic, readonly) UIColor *selectedColor;
- (void)refreshState;
@end
