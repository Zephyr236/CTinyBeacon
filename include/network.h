#ifndef NETWORK_H
#define NETWORK_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <curl/curl.h>
#include "config.h"
#include"crypto.h"
typedef struct {
    char* data;
    int size;
} HttpResponse;

size_t DummyWriteData(void *pPtr, size_t tSize, size_t tNmemb, void *pStream);
void SendPostRequest(const char *szUrl, unsigned char *pData, size_t tDataLength);
int ConnectAndSend(const char *szIp, int nPort, char *szHttpdata, int nHttpdataLen, char **ppResponse, int *pnResponseSize);
void PostResultAdvanced(const char *szIp, int nPort, char *szSessionId, const unsigned char *pResult, size_t tResultLen);
#endif
