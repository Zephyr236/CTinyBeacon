#include"../include/command.h"
BOOL ExecuteCommand(const char *szCommand, char **ppOutputBuffer, DWORD *pdwBufferSize, DWORD *pdwExitCode)
{
	HANDLE hReadPipe, hWritePipe;
	SECURITY_ATTRIBUTES stSa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};

	if (!CreatePipe(&hReadPipe, &hWritePipe, &stSa, 0))
	{
		return FALSE;
	}

	STARTUPINFO stSi;
	PROCESS_INFORMATION stPi;

	ZeroMemory(&stSi, sizeof(stSi));
	stSi.cb = sizeof(stSi);
	stSi.dwFlags = STARTF_USESTDHANDLES;
	stSi.hStdOutput = hWritePipe;
	stSi.hStdError = hWritePipe;

	ZeroMemory(&stPi, sizeof(stPi));

	BOOL bResult = CreateProcessA("C:\\Windows\\System32\\cmd.exe",
								  (LPSTR)szCommand,
								  NULL,
								  NULL,
								  TRUE,
								  0,
								  NULL,
								  NULL,
								  (LPSTARTUPINFOA)&stSi,
								  &stPi);
	if (bResult == 0)
	{
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);
		return FALSE;
	}

	CloseHandle(hWritePipe);

	*pdwBufferSize = INITIAL_BUFFER_SIZE;
	*ppOutputBuffer = (char *)malloc(*pdwBufferSize);
	if (*ppOutputBuffer == NULL)
	{
		CloseHandle(hReadPipe);
		CloseHandle(stPi.hProcess);
		CloseHandle(stPi.hThread);
		return FALSE;
	}

	DWORD dwTotalBytesRead = 0;
	DWORD dwBytesRead;
	do
	{
		if (dwTotalBytesRead + INITIAL_BUFFER_SIZE > *pdwBufferSize)
		{
			*pdwBufferSize *= 2;
			char *pNewBuffer = (char *)realloc(*ppOutputBuffer, *pdwBufferSize);
			if (pNewBuffer == NULL)
			{
				free(*ppOutputBuffer);
				CloseHandle(hReadPipe);
				CloseHandle(stPi.hProcess);
				CloseHandle(stPi.hThread);
				return FALSE;
			}
			*ppOutputBuffer = pNewBuffer;
		}

		dwBytesRead = ReadFromPipe(hReadPipe, *ppOutputBuffer + dwTotalBytesRead, *pdwBufferSize - dwTotalBytesRead);
		if (dwBytesRead > 0)
		{
			dwTotalBytesRead += dwBytesRead;
		}
	} while (dwBytesRead > 0);

	while (WaitForSingleObject(stPi.hProcess, 0) == WAIT_TIMEOUT)
	{
		Sleep(100);
	}

	if (!GetExitCodeProcess(stPi.hProcess, pdwExitCode))
	{
		free(*ppOutputBuffer);
		CloseHandle(hReadPipe);
		CloseHandle(stPi.hProcess);
		CloseHandle(stPi.hThread);
		return FALSE;
	}

	CloseHandle(hReadPipe);
	CloseHandle(stPi.hProcess);
	CloseHandle(stPi.hThread);

	return bResult;
}
