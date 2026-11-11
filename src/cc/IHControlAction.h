#import <Foundation/Foundation.h>

// 控制中心开启时自动启用插件，关闭时只停止热点。
FOUNDATION_EXPORT NSDictionary * _Nullable IHSetHotspotFromControlCenter(BOOL selected, NSError * _Nullable * _Nullable error);
