#pragma once
#include <Windows.h>
#include <wincrypt.h>



__declspec(dllexport) BOOL WINAPI VerifyPEFile(
	PCWSTR FilePath,
	LONG* VerifyResult,
	PCCERT_CONTEXT** SignaturesOut,
	DWORD* SignatureCountOut
);

__declspec(dllexport) VOID WINAPI FreeCertInfo(
	PCCERT_CONTEXT* Signatures,
	DWORD SignatureCount
);

BOOL LoadDependencies();
