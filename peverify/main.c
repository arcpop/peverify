#include "verify.h"
BOOL LoadDependencies();


DWORD WINAPI DllMain(HMODULE Dll, DWORD Reason, LPVOID Reserved)
{
	if (Reason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(Dll);
		return LoadDependencies();
	}
	return TRUE;
}