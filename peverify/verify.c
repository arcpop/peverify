#include "verify.h"

#include <stdio.h>
#include <SoftPub.h>
#include <WinTrust.h>
#include <mscat.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "Crypt32.lib")

static GUID WinTrustActionGenericVerifyV2	= WINTRUST_ACTION_GENERIC_VERIFY_V2;
static GUID DriverActionVerify				= DRIVER_ACTION_VERIFY;

BOOL (WINAPI *pfnCryptCATAdminAcquireContext)(
	_Out_       HCATADMIN *phCatAdmin,
	_In_  const GUID      *pgSubsystem,
	_In_        DWORD     dwFlags
);
BOOL (WINAPI* pfnCryptCATAdminReleaseContext)(
	_In_ HCATADMIN hCatAdmin,
	_In_ DWORD     dwFlags
);
BOOL(WINAPI *pfnCryptCATAdminCalcHashFromFileHandle)(
	_In_    HANDLE hFile,
	_Inout_ DWORD  *pcbHash,
	_In_    BYTE   *pbHash,
	_In_    DWORD  dwFlags
	);
HCATINFO (WINAPI *pfnCryptCATAdminEnumCatalogFromHash)(
	_In_ HCATADMIN hCatAdmin,
	_In_ BYTE      *pbHash,
	_In_ DWORD     cbHash,
	_In_ DWORD     dwFlags,
	_In_ HCATINFO  *phPrevCatInfo
);

BOOL (WINAPI* pfnCryptCATCatalogInfoFromContext)(
	_In_    HCATINFO     hCatInfo,
	_Inout_ CATALOG_INFO *psCatInfo,
	_In_    DWORD        dwFlags
);
BOOL(WINAPI* pfnCryptCATAdminReleaseCatalogContext)(
	_In_ HCATADMIN hCatAdmin,
	_In_ HCATINFO  hCatInfo,
	_In_ DWORD     dwFlags
);

BOOL(WINAPI *pfnCryptCATAdminAcquireContext2)(
	_Out_            HCATADMIN               *phCatAdmin,
	_In_opt_   const GUID                    *pgSubsystem,
	_In_opt_         PCWSTR                  pwszHashAlgorithm,
	_In_opt_         PCCERT_STRONG_SIGN_PARA pStrongHashPolicy,
	_Reserved_       DWORD                   dwFlags
	);
BOOL(WINAPI *pfnCryptCATAdminCalcHashFromFileHandle2)(
	_In_       HCATADMIN                                        hCatAdmin,
	_In_       HANDLE                                           hFile,
	_Inout_    DWORD                                            *pcbHash,
	_Out_writes_bytes_to_opt_(*pcbHash, *pcbHash)BYTE *pbHash,
	_Reserved_ DWORD                                            dwFlags
	);

BOOL LoadDependencies()
{
	HMODULE hWinTrustDll = LoadLibraryW(L"wintrust.dll");

	if (hWinTrustDll == NULL)
	{
		return FALSE;
	}

	pfnCryptCATAdminAcquireContext = (LPVOID)GetProcAddress(hWinTrustDll, "CryptCATAdminAcquireContext");
	pfnCryptCATAdminCalcHashFromFileHandle = (LPVOID)GetProcAddress(hWinTrustDll, "CryptCATAdminCalcHashFromFileHandle");
	pfnCryptCATCatalogInfoFromContext = (LPVOID)GetProcAddress(hWinTrustDll, "CryptCATCatalogInfoFromContext");
	pfnCryptCATAdminEnumCatalogFromHash = (LPVOID)GetProcAddress(hWinTrustDll, "CryptCATAdminEnumCatalogFromHash");
	pfnCryptCATAdminReleaseCatalogContext = (LPVOID)GetProcAddress(hWinTrustDll, "CryptCATAdminReleaseCatalogContext");
	pfnCryptCATAdminReleaseContext = (LPVOID)GetProcAddress(hWinTrustDll, "CryptCATAdminReleaseContext");
	if (pfnCryptCATAdminAcquireContext == NULL ||
		pfnCryptCATAdminCalcHashFromFileHandle == NULL ||
		pfnCryptCATCatalogInfoFromContext == NULL ||
		pfnCryptCATAdminEnumCatalogFromHash == NULL ||
		pfnCryptCATAdminReleaseContext == NULL
		)
	{
		return FALSE;
	}

	//Check for advanced functions (available since Windows 8)
	pfnCryptCATAdminAcquireContext2 = (LPVOID)GetProcAddress(hWinTrustDll, "CryptCATAdminAcquireContext2");
	pfnCryptCATAdminCalcHashFromFileHandle2 = (LPVOID)GetProcAddress(hWinTrustDll, "CryptCATAdminCalcHashFromFileHandle2");

	//Either both should be available or none of them
	if (pfnCryptCATAdminAcquireContext2 != NULL && pfnCryptCATAdminCalcHashFromFileHandle2 == NULL)
	{
		return FALSE;
	}
	if (pfnCryptCATAdminAcquireContext2 == NULL && pfnCryptCATAdminCalcHashFromFileHandle2 != NULL)
	{
		return FALSE;
	}
	return TRUE;
}

BOOL ExtractCertInfo(
	HANDLE StateHandle,
	PCCERT_CONTEXT** SignaturesOut,
	DWORD* SignatureCountOut
)
{
	PCRYPT_PROVIDER_DATA providerData;
	PCRYPT_PROVIDER_SGNR signer;
	ULONG i;
	*SignaturesOut = NULL;
	*SignatureCountOut = 0;
	providerData = WTHelperProvDataFromStateData(StateHandle);
	if (providerData == NULL)
	{
		return FALSE;
	}

	i = 0;

	while (signer = WTHelperGetProvSignerFromChain(providerData, i, FALSE, 0))
	{
		if (signer->csCertChain != 0)
		{
			break;
		}
		i++;
	}
	if (signer != NULL)
	{
		PCCERT_CONTEXT* signatures = HeapAlloc(GetProcessHeap(), 0, signer->csCertChain * sizeof(PCCERT_CONTEXT));
		if (signatures == NULL)
		{
			return FALSE;
		}

		for (i = 0; i < signer->csCertChain; i++)
		{
			signatures[i] = CertDuplicateCertificateContext(signer->pasCertChain[i].pCert);
		}
		*SignaturesOut = signatures;
		*SignatureCountOut = signer->csCertChain;
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

LONG VerifyTrust(
	DWORD UnionChoice,
	LPVOID VerifyStruct,
	DWORD ProviderFlags,
	LPGUID ActionID,
	LPVOID ActionParameter,
	HANDLE* StateDataOut
)
{
	LONG res;
	WINTRUST_DATA winTrustData = { 0 };
	winTrustData.cbStruct = sizeof(winTrustData);
	winTrustData.pPolicyCallbackData = ActionParameter;
	winTrustData.dwUIChoice = WTD_UI_NONE;
	winTrustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
	winTrustData.dwUnionChoice = UnionChoice; //Embedded or Catalog Cert.
	winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	winTrustData.pwszURLReference = NULL;
	winTrustData.dwProvFlags = ProviderFlags | WTD_SAFER_FLAG; //See documentation
	(LPVOID)winTrustData.pFile = VerifyStruct;
	res = WinVerifyTrust(INVALID_HANDLE_VALUE, ActionID, &winTrustData);
	*StateDataOut = winTrustData.hWVTStateData;
	//printf("Verify trust: %d -> %d\n", UnionChoice, res);
	return res;
}

VOID FreeWVTStateData(
	HANDLE StateData,
	LPGUID ActionID
)
{
	WINTRUST_DATA winTrustData = { 0 };
	winTrustData.hWVTStateData = StateData;
	winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(NULL, ActionID, &winTrustData);
}

BOOL CalculateFileHash(
	HCATADMIN CatAdminHandle,
	HANDLE FileHandle,
	DWORD* HashLengthOut,
	PBYTE* HashOut
)
{
	DWORD fileHashLength = 32;
	PBYTE fileHash = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 32);

	if (fileHash == NULL)
	{
		return FALSE;
	}

	//Check if advanced version available
	if (pfnCryptCATAdminCalcHashFromFileHandle2)
	{
		if (!pfnCryptCATAdminCalcHashFromFileHandle2(CatAdminHandle, FileHandle, &fileHashLength, fileHash, 0))
		{
			HeapFree(GetProcessHeap(), 0, fileHash);
			fileHash = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileHashLength);
			if (fileHash == NULL)
			{
				return FALSE;
			}
			if (!pfnCryptCATAdminCalcHashFromFileHandle2(CatAdminHandle, FileHandle, &fileHashLength, fileHash, 0))
			{
				HeapFree(GetProcessHeap(), 0, fileHash);
				return FALSE;
			}
		}
		*HashOut = fileHash;
		*HashLengthOut = fileHashLength;
		return TRUE;
	}
	else
	{
		if (!pfnCryptCATAdminCalcHashFromFileHandle(FileHandle, &fileHashLength, fileHash, 0))
		{
			HeapFree(GetProcessHeap(), 0, fileHash);
			fileHash = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileHashLength);
			if (fileHash == NULL)
			{
				return FALSE;
			}
			if (!pfnCryptCATAdminCalcHashFromFileHandle(FileHandle, &fileHashLength, fileHash, 0))
			{
				HeapFree(GetProcessHeap(), 0, fileHash);
				return FALSE;
			}
		}
	}
	*HashOut = fileHash;
	*HashLengthOut = fileHashLength;
	return TRUE;
}
PWSTR BinaryToHexString(PBYTE BinaryData, DWORD Length)
{
	DWORD i = 0;
	PWSTR StrOut = HeapAlloc(GetProcessHeap(), 0, (1 + (Length * 2)) * sizeof(WCHAR));
	if (StrOut == NULL)
	{
		return StrOut;
	}
	for (; i < Length; i++)
	{
		swprintf_s(StrOut + (2 * i), 3, L"%.2X", BinaryData[i]);
	}
	StrOut[2 * i] = L'\0';
	//printf("%ws\n", StrOut);
	return StrOut;
}

BOOL VerifyTrustFromCatalogCert(
	PCWSTR FilePath,
	HANDLE FileHandle,
	PCWSTR HashAlgorithm,
	BOOL DoRevocationChecks,
	LONG *WinTrustResult,
	HANDLE *StateDataOut
)
{
	HANDLE catAdminHandle;
	DWORD fileHashLength;
	PBYTE fileHash;
	BOOL Result = FALSE;

	if (pfnCryptCATAdminAcquireContext2)
	{
		if (!pfnCryptCATAdminAcquireContext2(&catAdminHandle, &DriverActionVerify, HashAlgorithm, NULL, 0))
		{
			return FALSE;
		}
	}
	else
	{
		if (!pfnCryptCATAdminAcquireContext(&catAdminHandle, &DriverActionVerify, 0))
		{
			return FALSE;
		}
	}

	if (CalculateFileHash(catAdminHandle, FileHandle, &fileHashLength, &fileHash))
	{
		PWSTR MemberTag = BinaryToHexString(fileHash, fileHashLength);
		if (MemberTag)
		{
			HANDLE catInfoHandle = pfnCryptCATAdminEnumCatalogFromHash(
				catAdminHandle,
				fileHash,
				fileHashLength,
				0,
				NULL
			);
			if (catInfoHandle)
			{
				CATALOG_INFO catInfo = { 0 };
				if (pfnCryptCATCatalogInfoFromContext(catAdminHandle, &catInfo, 0))
				{
					DWORD providerFlags = WTD_USE_DEFAULT_OSVER_CHECK | WTD_DISABLE_MD2_MD4 | WTD_SAFER_FLAG;
					DRIVER_VER_INFO verInfo = { 0 };
					WINTRUST_CATALOG_INFO winTrustCatInfo = { 0 };
					verInfo.cbStruct = sizeof(verInfo);
					winTrustCatInfo.cbStruct = sizeof(winTrustCatInfo);
					winTrustCatInfo.hCatAdmin = catAdminHandle;
					winTrustCatInfo.pcwszCatalogFilePath = catInfo.wszCatalogFile;
					winTrustCatInfo.pcwszMemberFilePath = FilePath;
					winTrustCatInfo.pcwszMemberTag = MemberTag;
					winTrustCatInfo.pbCalculatedFileHash = fileHash;
					winTrustCatInfo.cbCalculatedFileHash = fileHashLength;
					if(DoRevocationChecks)
					{
						providerFlags |= WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN;
					}
					*WinTrustResult = VerifyTrust(
						WTD_CHOICE_CATALOG,
						&winTrustCatInfo,
						providerFlags,
						&DriverActionVerify,
						&verInfo,
						StateDataOut
					);

					if (verInfo.pcSignerCertContext)
					{
						CertFreeCertificateContext(verInfo.pcSignerCertContext);
					}
					Result = TRUE;
				}
				pfnCryptCATAdminReleaseCatalogContext(catAdminHandle, catInfoHandle, 0);
			}
			HeapFree(GetProcessHeap(), 0, MemberTag);
		}
		pfnCryptCATAdminReleaseContext(catAdminHandle, 0);
	}
	return Result;
}
BOOL VerifyTrustFromEmbeddedCert(
	PCWSTR FilePath,
	HANDLE FileHandle,
	BOOL DoRevocationChecks,
	LONG *WinTrustResult,
	HANDLE *StateDataOut
)
{
	DWORD providerFlags = WTD_SAFER_FLAG;
	WINTRUST_FILE_INFO fileInfo = { 0 };
	fileInfo.cbStruct = sizeof(fileInfo);
	fileInfo.pcwszFilePath = FilePath;
	fileInfo.hFile = FileHandle;

	if (DoRevocationChecks)
	{
		providerFlags |= WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN;
	}

	*WinTrustResult = VerifyTrust(
		WTD_CHOICE_FILE,
		&fileInfo,
		providerFlags,
		&WinTrustActionGenericVerifyV2,
		NULL,
		StateDataOut
	);
	return TRUE;
}

INT WINAPI VerifyPEFile(
	PCWSTR FilePath,
	LONG* VerifyResult,
	PCCERT_CONTEXT** SignaturesOut,
	DWORD* SignatureCountOut
)
{
	LONG winTrustRes;
	HANDLE stateData = NULL;
	HANDLE fileHandle;
	fileHandle = CreateFileW(
		FilePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		return -1;
	}
	*VerifyResult = TRUST_E_NOSIGNATURE;
	winTrustRes = TRUST_E_NOSIGNATURE;
	stateData = NULL;
	if (VerifyTrustFromEmbeddedCert(FilePath, fileHandle, FALSE, &winTrustRes, &stateData))
	{
		*VerifyResult = winTrustRes;
		if (winTrustRes == 0)
		{
			ExtractCertInfo(stateData, SignaturesOut, SignatureCountOut);
			FreeWVTStateData(stateData, &WinTrustActionGenericVerifyV2);
			stateData = NULL;
		}
		CloseHandle(fileHandle);
		return 0;
	}
	if (pfnCryptCATAdminAcquireContext2 && pfnCryptCATAdminCalcHashFromFileHandle2)
	{
		winTrustRes = TRUST_E_NOSIGNATURE;
		stateData = NULL;
		if (VerifyTrustFromCatalogCert(FilePath, fileHandle, BCRYPT_SHA256_ALGORITHM, FALSE, &winTrustRes, &stateData))
		{
			printf("Result is 0x%.8X\n", winTrustRes);
			*VerifyResult = winTrustRes;
			if (winTrustRes == 0)
			{
				ExtractCertInfo(stateData, SignaturesOut, SignatureCountOut);
				FreeWVTStateData(stateData, &DriverActionVerify);
				stateData = NULL;
			}
			CloseHandle(fileHandle);
			return 0;
		}
	}
	winTrustRes = TRUST_E_NOSIGNATURE;
	stateData = NULL;
	if (VerifyTrustFromCatalogCert(FilePath, fileHandle, NULL, TRUE, &winTrustRes, &stateData))
	{
		printf("Result is 0x%.8X\n", winTrustRes);
		*VerifyResult = winTrustRes;
		if (winTrustRes == 0)
		{
			ExtractCertInfo(stateData, SignaturesOut, SignatureCountOut);
			FreeWVTStateData(stateData, &DriverActionVerify);
			stateData = NULL;
		}
		CloseHandle(fileHandle);
		return 0;
	}
	CloseHandle(fileHandle);
	return -2;
}

VOID WINAPI FreeCertInfo(PCCERT_CONTEXT *Signatures, DWORD SignatureCount)
{
	for (DWORD i = 0; i < SignatureCount; i++)
	{
		CertFreeCertificateContext(Signatures[i]);
	}
	HeapFree(GetProcessHeap(), 0, (LPVOID)Signatures);
}

