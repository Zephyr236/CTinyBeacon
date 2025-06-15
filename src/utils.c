#include"../include/utils.h"

DWORD ReadFromPipe(HANDLE hPipe, char *pBuffer, DWORD dwBufferSize)
{
	DWORD dwBytesAvailable;
	DWORD dwBytesRead = 0;
	DWORD dwStartTime = GetTickCount();

	if (!PeekNamedPipe(hPipe, NULL, 0, NULL, &dwBytesAvailable, NULL))
	{
		printf("PeekNamedPipe failed with error: %d\n", GetLastError());
		return 0;
	}

	if (dwBytesAvailable > 0)
	{
		if (!ReadFile(hPipe, pBuffer, min(dwBufferSize, dwBytesAvailable), &dwBytesRead, NULL))
		{
			printf("ReadFile failed with error: %d\n", GetLastError());
			return 0;
		}
		pBuffer[dwBytesRead] = '\0';
		return dwBytesRead;
	}
	else
	{
		while (GetTickCount() - dwStartTime < TIMEOUT)
		{
			if (!PeekNamedPipe(hPipe, NULL, 0, NULL, &dwBytesAvailable, NULL))
			{
				printf("PeekNamedPipe failed with error: %d\n", GetLastError());
				return 0;
			}
			if (dwBytesAvailable > 0)
			{
				if (!ReadFile(hPipe, pBuffer, min(dwBufferSize, dwBytesAvailable), &dwBytesRead, NULL))
				{
					printf("ReadFile failed with error: %d\n", GetLastError());
					return 0;
				}
				pBuffer[dwBytesRead] = '\0';
				return dwBytesRead;
			}
			Sleep(100);
		}
		return 0;
	}
}

BOOL Base64Encode(const BYTE *pbInput, DWORD dwInputLen, char **ppchBase64Output, DWORD *pdwBase64OutputLen)
{
	if (pbInput == NULL || ppchBase64Output == NULL || pdwBase64OutputLen == NULL)
	{
		return FALSE;
	}
	if (!CryptBinaryToStringA(pbInput, dwInputLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, pdwBase64OutputLen))
	{
		return FALSE;
	}
	*ppchBase64Output = (char *)malloc(*pdwBase64OutputLen + 1);
	if (*ppchBase64Output == NULL)
	{
		return FALSE;
	}
	memset(*ppchBase64Output, 0x00, *pdwBase64OutputLen + 1);
	if (!CryptBinaryToStringA(pbInput, dwInputLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, *ppchBase64Output, pdwBase64OutputLen))
	{
		free(*ppchBase64Output);
		*ppchBase64Output = NULL;
		return FALSE;
	}
	return TRUE;
}

BOOL Base64Decode(const char *pchBase64Input, DWORD dwBase64InputLen, BYTE **ppbOutput, DWORD *pdwOutputLen)
{
	if (pchBase64Input == NULL || ppbOutput == NULL || pdwOutputLen == NULL)
	{
		return FALSE;
	}

	if (!CryptStringToBinaryA(pchBase64Input, dwBase64InputLen, CRYPT_STRING_BASE64, NULL, pdwOutputLen, NULL, NULL))
	{
		return FALSE;
	}

	*ppbOutput = (BYTE *)malloc(*pdwOutputLen + 1);
	if (*ppbOutput == NULL)
	{
		return FALSE;
	}
	memset(*ppbOutput, 0x00, *pdwOutputLen + 1);

	if (!CryptStringToBinaryA(pchBase64Input, dwBase64InputLen, CRYPT_STRING_BASE64, *ppbOutput, pdwOutputLen, NULL, NULL))
	{
		free(*ppbOutput);
		*ppbOutput = NULL;
		return FALSE;
	}

	return TRUE;
}

void Init(char *szCookie, int nCookieLen, char *szHost, int nHostLen)
{
	g_nHttpLen = 39 + 108 + 53 + nCookieLen + nHostLen;
	g_szHttp = (char *)malloc(g_nHttpLen);
	memcpy(g_szHttp, abPeer0_0, 39);
	memcpy(g_szHttp + 39, szCookie, nCookieLen);
	memcpy(g_szHttp + 39 + nCookieLen, abPeer0_0 + 211, 108);
	memcpy(g_szHttp + 39 + nCookieLen + 108, szHost, nHostLen);
	memcpy(g_szHttp + 39 + nCookieLen + 108 + nHostLen, abPeer0_0 + 333, 53);
}