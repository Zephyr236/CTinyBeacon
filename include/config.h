#ifndef CONFIG_H
#define CONFIG_H
#include <openssl/rsa.h>
#define INITIAL_BUFFER_SIZE 1024
#define TIMEOUT 3000
extern const int nPadding;

// 全局配置
extern char *szIpAddress;
extern int nPort;
extern int nSleepTime;

// 加密相关配置
extern unsigned char abHexData[83];
extern unsigned char abPublicKey[];
extern char abAesKey[];
extern char abCsFixedIV[];
extern char abPeer0_0[];
extern char abPost0_0[];
extern unsigned char abSharedKey[];
extern unsigned char abHmacKey[];
extern unsigned char abIv[];

// 其他全局变量
extern unsigned char *g_pPostData;
extern unsigned char *g_pRepPostData;
extern int g_nPostLen;
extern int g_nReqPostLen;
extern unsigned char g_abEncryptedStr[128];
extern char *g_szHttp;
extern int g_nHttpLen;
extern char g_szSessionId[20];
extern int nCount;

#endif
