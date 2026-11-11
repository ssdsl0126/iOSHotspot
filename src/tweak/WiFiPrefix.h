#pragma once
#import <Foundation/Foundation.h>
#include <sys/types.h>
BOOL IHWiFiPrefixInstall(void);
BOOL IHWiFiPrefixIsReady(void);
void IHWiFiPrefixFilter(int *name,unsigned count,void *value,size_t *length,size_t capacity);
BOOL IHWiFiPrefixPrepareRA(void);
