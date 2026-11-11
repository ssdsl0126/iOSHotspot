#import "IHQRCode.h"
#include "../../third_party/qrcodegen/c/qrcodegen.h"
#include <stdlib.h>
#include <string.h>

static void releasePixels(void *info,const void *data,size_t length){free((void*)data);}
CGImageRef IHCreateQRCodeImage(NSString *payload){
 if(!payload.length)return NULL;
 uint8_t *temporary=malloc(qrcodegen_BUFFER_LEN_MAX),*code=malloc(qrcodegen_BUFFER_LEN_MAX);
 if(!temporary||!code){free(temporary);free(code);return NULL;}
 BOOL okay=qrcodegen_encodeText(payload.UTF8String,temporary,code,qrcodegen_Ecc_MEDIUM,qrcodegen_VERSION_MIN,qrcodegen_VERSION_MAX,qrcodegen_Mask_AUTO,true);
 free(temporary);if(!okay){free(code);return NULL;}
 int modules=qrcodegen_getSize(code),quiet=4,scale=700/(modules+2*quiet);if(scale<1){free(code);return NULL;}
 size_t side=(size_t)(modules+2*quiet)*(size_t)scale,length=side*side;uint8_t *pixels=malloc(length);if(!pixels){free(code);return NULL;}
 memset(pixels,255,length);
 // 直接建立灰度像素，保留四模块静区和整数倍缩放，不创建任何CoreImage/OpenGL上下文。
 for(int y=0;y<modules;y++)for(int x=0;x<modules;x++)if(qrcodegen_getModule(code,x,y))
  for(int row=0;row<scale;row++)memset(pixels+((size_t)(y+quiet)*scale+row)*side+(size_t)(x+quiet)*scale,0,(size_t)scale);
 free(code);CGColorSpaceRef space=CGColorSpaceCreateDeviceGray();CGDataProviderRef provider=CGDataProviderCreateWithData(NULL,pixels,length,releasePixels);
 if(!space||!provider){if(space)CGColorSpaceRelease(space);if(provider)CGDataProviderRelease(provider);else free(pixels);return NULL;}
 CGImageRef image=CGImageCreate(side,side,8,8,side,space,kCGImageAlphaNone,provider,NULL,false,kCGRenderingIntentDefault);
 CGDataProviderRelease(provider);CGColorSpaceRelease(space);return image;
}
