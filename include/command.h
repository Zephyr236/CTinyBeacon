#ifndef COMMAND_H
#define COMMAND_H

#include <windows.h>
#include"config.h"
#include"utils.h"
BOOL ExecuteCommand(const char *szCommand, char **ppOutputBuffer, DWORD *pdwBufferSize, DWORD *pdwExitCode);
#endif
