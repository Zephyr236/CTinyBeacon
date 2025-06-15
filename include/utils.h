#ifndef UTILS_H
#define UTILS_H

#include <windows.h>
#include"../include/config.h"

DWORD ReadFromPipe(HANDLE hPipe, char *pBuffer, DWORD dwBufferSize);
BOOL Base64Encode(const BYTE *pbInput, DWORD dwInputLen, char **ppchBase64Output, DWORD *pdwBase64OutputLen);
BOOL Base64Decode(const char *pchBase64Input, DWORD dwBase64InputLen, BYTE **ppbOutput, DWORD *pdwOutputLen);
void Init(char *szCookie, int nCookieLen, char *szHost, int nHostLen);

#endif
