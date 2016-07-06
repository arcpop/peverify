#include "../peverify/verify.h"
#include <tchar.h>
#include <stdio.h>
#include <Psapi.h>
#include <winternl.h>

#pragma comment(lib, "crypt32.lib")


NTSTATUS (WINAPI *pfnNtQuerySystemInformation)(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength
);



VOID PrintCertInfo(PCCERT_CONTEXT* Signatures, DWORD SignatureCount)
{
	WCHAR SubjectBuffer[MAX_PATH];
	WCHAR IssuerBuffer[MAX_PATH];

	for (DWORD i = 0; i < SignatureCount; i++)
	{
		SubjectBuffer[0] = L'\0';
		IssuerBuffer[0] = L'\0';
		CertNameToStrW(Signatures[i]->dwCertEncodingType, &Signatures[i]->pCertInfo->Subject, CERT_X500_NAME_STR, SubjectBuffer, MAX_PATH);
		CertNameToStrW(Signatures[i]->dwCertEncodingType, &Signatures[i]->pCertInfo->Issuer, CERT_X500_NAME_STR, IssuerBuffer, MAX_PATH);
		wprintf(L"\t%ws -> %ws\n", IssuerBuffer, SubjectBuffer);
	}
}

VOID PrintInfoForProcess(DWORD pid)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (hProcess != NULL)
	{
		LONG VerifyResult;
		PCCERT_CONTEXT* Signatures = NULL;
		DWORD SignatureCount = 0;
		WCHAR ExeFileName[MAX_PATH] = { 0 };
		if (GetModuleFileNameExW(hProcess, NULL, ExeFileName, MAX_PATH) != 0)
		{
			if (VerifyPEFile(ExeFileName, &VerifyResult, &Signatures, &SignatureCount))
			{
				wprintf(L"%ws (0x%.8X) %d:\n", ExeFileName, VerifyResult, SignatureCount);
				PrintCertInfo(Signatures, SignatureCount);
			}
			else
			{
				wprintf(L"%ws failed\n", ExeFileName);
			}
		}
		else
		{
			wprintf(L"Failed to get module file name of %d\n", pid);
		}
		CloseHandle(hProcess);
	}
	else
	{
		wprintf(L"Failed to open %d\n", pid);
	}
}


VOID PrintInfoForAllProcesses()
{
	ULONG ProcessInfoCount = 1024;
	SYSTEM_PROCESS_INFORMATION* ProcessInfo;
	ULONG Needed = 0;

	for (
		ProcessInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ProcessInfoCount * sizeof(SYSTEM_PROCESS_INFORMATION));
		ProcessInfo != NULL;
		ProcessInfo = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ProcessInfo, ProcessInfoCount * sizeof(SYSTEM_PROCESS_INFORMATION))
		)
	{
		Needed = 0;
		if (0 == pfnNtQuerySystemInformation(
			SystemProcessInformation,
			ProcessInfo,
			sizeof(SYSTEM_PROCESS_INFORMATION) * ProcessInfoCount,
			&Needed))
		{
			break;
		}
		ProcessInfoCount = (Needed / sizeof(SYSTEM_PROCESS_INFORMATION)) + 5;
	}
	if (ProcessInfo == NULL)
	{
		return;
	}
	ProcessInfoCount = (Needed / sizeof(SYSTEM_PROCESS_INFORMATION));
	for (ULONG i = 0; i < ProcessInfoCount; i++)
	{
		PrintInfoForProcess((DWORD)ProcessInfo[i].UniqueProcessId);
	}
}

int _tmain(int argc, TCHAR* argv[])
{
	HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
	pfnNtQuerySystemInformation = (LPVOID)GetProcAddress(hNtDll, "NtQuerySystemInformation");

	if (argc > 1)
	{
		DWORD pid = _ttoi(argv[1]);
		PrintInfoForProcess(pid);
	}
	else
	{
		PrintInfoForAllProcesses();
	}
}

