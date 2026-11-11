// 用自有CoreGraphics矢量绘制热点图标，不依赖运行时图形框架或外部图片。
import Foundation
import CoreGraphics
import ImageIO
let folder = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
for (name, size) in [("AppIcon60x60@2x.png",120),("AppIcon60x60@3x.png",180),("AppIcon76x76@2x.png",152),("SettingsIcon@2x.png",58),("SettingsIcon@3x.png",87)] {
    let space = CGColorSpaceCreateDeviceRGB()
    let context = CGContext(data:nil,width:size,height:size,bitsPerComponent:8,bytesPerRow:size*4,space:space,bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue)!
    context.scaleBy(x:CGFloat(size)/180,y:CGFloat(size)/180)
    // 设置列表不会自动裁切图标，生成透明圆角；主屏幕图标仍由系统裁切。
    if name.hasPrefix("SettingsIcon") {
        context.addPath(CGPath(roundedRect:CGRect(x:0,y:0,width:180,height:180),cornerWidth:40,cornerHeight:40,transform:nil))
        context.clip()
    }
    context.setFillColor(CGColor(red:0.04,green:0.65,blue:0.37,alpha:1));context.fill(CGRect(x:0,y:0,width:180,height:180))
    context.setStrokeColor(CGColor(gray:1,alpha:1));context.setFillColor(CGColor(gray:1,alpha:1));context.setLineWidth(10);context.setLineCap(.round)
    for radius: CGFloat in [33,60] {
        context.addArc(center:CGPoint(x:90,y:90),radius:radius,startAngle:CGFloat.pi*0.67,endAngle:CGFloat.pi*1.33,clockwise:false);context.strokePath()
        context.addArc(center:CGPoint(x:90,y:90),radius:radius,startAngle:-CGFloat.pi*0.33,endAngle:CGFloat.pi*0.33,clockwise:false);context.strokePath()
    }
    context.fillEllipse(in:CGRect(x:80,y:80,width:20,height:20))
    let image = context.makeImage()!, target = folder.appendingPathComponent(name)
    let destination = CGImageDestinationCreateWithURL(target as CFURL,"public.png" as CFString,1,nil)!
    CGImageDestinationAddImage(destination,image,nil);precondition(CGImageDestinationFinalize(destination))
}
