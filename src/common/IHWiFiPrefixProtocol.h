#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

// Darwin 64位公开in6_prefix ABI；末尾跟随advrtrs个sockaddr_in6。
typedef struct {
 uint8_t address[28],raFlags,prefixLength,origin,reserved;
 uint64_t validLifetime,preferredLifetime,expire;
 uint32_t flags;int32_t references;
 uint16_t interfaceIndex,advertisingRouters;uint32_t padding;
} IHWiFiPrefixRecord;
_Static_assert(sizeof(IHWiFiPrefixRecord)==72,"in6_prefix ABI不符");

// 先完整校验变长表，再整理本进程的查询副本，绝不写入内核前缀表。
static bool IHWiFiPreferGlobalPrefixes(void *buffer,size_t *length,size_t capacity,unsigned index){
 if(!buffer||!length||!index||*length>capacity||*length>1048576)return false;
 unsigned char *bytes=buffer;bool global=false;size_t position=0;
 while(position<*length){
  if(*length-position<sizeof(IHWiFiPrefixRecord))return false;
  IHWiFiPrefixRecord entry;memcpy(&entry,bytes+position,sizeof(entry));
  size_t size=sizeof(entry)+(size_t)entry.advertisingRouters*28;
  if(size>*length-position||entry.address[0]!=28||entry.address[1]!=30||entry.prefixLength>128)return false;
  if(entry.interfaceIndex==index&&entry.prefixLength==64&&entry.advertisingRouters&&entry.validLifetime&&entry.preferredLifetime&&(entry.address[8]&0xe0)==0x20)global=true;
  position+=size;
 }
 if(!global)return false;
 size_t output=0;position=0;
 while(position<*length){
  IHWiFiPrefixRecord entry;memcpy(&entry,bytes+position,sizeof(entry));size_t size=sizeof(entry)+(size_t)entry.advertisingRouters*28;
  if(!(entry.interfaceIndex==index&&(entry.address[8]&0xfe)==0xfc)){memmove(bytes+output,bytes+position,size);output+=size;}
  position+=size;
 }
 *length=output;return true;
}

// 只允许当前Wi-Fi真实公网/64中的地址触发组播订阅。
static bool IHWiFiSolicitedGroup(const uint8_t address[16],const uint8_t *prefixes,size_t count,uint8_t group[16]){
 if(!address||!prefixes||!group||(address[0]&0xe0)!=0x20)return false;
 bool match=false;for(size_t i=0;i<count;i++)if(!memcmp(address,prefixes+i*8,8)){match=true;break;}
 if(!match)return false;
 memset(group,0,16);group[0]=0xff;group[1]=2;group[11]=1;group[12]=0xff;memcpy(group+13,address+13,3);return true;
}
