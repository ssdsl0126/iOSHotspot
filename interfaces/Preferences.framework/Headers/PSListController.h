#pragma once
#import <UIKit/UIKit.h>
// 不声明或访问系统私有实例字段，通过具名属性把列表交给系统表格管理。
@interface PSListController : UIViewController
@property(nonatomic, strong) NSMutableArray *specifiers;
- (void)reloadSpecifiers;
@end
