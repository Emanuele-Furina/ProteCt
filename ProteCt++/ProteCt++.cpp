// ProteCt++.cpp : Definisce le funzioni per la libreria statica.

#include "pch.h"
#include "framework.h"
#include <iostream>
#include "./ProteCt++.h"
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <wincrypt.h>

typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
	IN HANDLE           ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID           ProcessInformation,
	IN ULONG            ProcessInformationLength,
	OUT PULONG          ReturnLength
	);

constexpr size_t SHA256_HASH_SIZE = 32;
constexpr size_t BUFFER_SIZE = 4096;

/**
 * @brief Classe RAII per gestire automaticamente l'handle del file.
 */
class FileHandle {
public:
	FileHandle(HANDLE handle) : handle_(handle) {}
	~FileHandle() {
		if (handle_ != INVALID_HANDLE_VALUE) {
			CloseHandle(handle_);
		}
	}
	HANDLE get() const { return handle_; }
private:
	HANDLE handle_;
};

/**
 * @brief Classe RAII per gestire automaticamente il contesto di crittografia.
 */
class CryptContext {
public:
	CryptContext() : hProv_(NULL) {
		if (!CryptAcquireContext(&hProv_, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
			hProv_ = NULL;
		}
	}
	~CryptContext() {
		if (hProv_) {
			CryptReleaseContext(hProv_, 0);
		}
	}
	HCRYPTPROV get() const { return hProv_; }
	bool isValid() const { return hProv_ != NULL; }
private:
	HCRYPTPROV hProv_;
};

/**
 * @brief Classe RAII per gestire automaticamente l'oggetto hash.
 */
class CryptHash {
public:
	CryptHash(HCRYPTPROV hProv) : hHash_(NULL) {
		if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash_)) {
			hHash_ = NULL;
		}
	}
	~CryptHash() {
		if (hHash_) {
			CryptDestroyHash(hHash_);
		}
	}
	HCRYPTHASH get() const { return hHash_; }
	bool isValid() const { return hHash_ != NULL; }
private:
	HCRYPTHASH hHash_;
};

/**
 * @brief Verifica se la libreria è caricata.
 *
 * @return true se la libreria è caricata, altrimenti false.
 */
bool IsLibraryLoaded() {
	return true;
}

/**
 * @brief Controlla se un debugger semplice è presente.
 *
 * @return true se un debugger è presente, altrimenti false.
 */
bool IsSimpleDebuggerPresent() {
	return IsDebuggerPresent();
}

/**
 * @brief Controlla se un debugger remoto è presente.
 *
 * @return true se un debugger remoto è presente, altrimenti false.
 */
bool CheckRemoteDebugger() {
	BOOL bDebuggerPresent;
	return CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent) && bDebuggerPresent;
}

/**
 * @brief Controlla se il processo è in debug tramite il ProcessDebugPort.
 *
 * @return true se il processo è in debug, altrimenti false.
 */
bool CheckProcessDebugPort() {
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	if (hNtdll) {
		auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
		if (pfnNtQueryInformationProcess) {
			DWORD dwProcessDebugPort, dwReturned;
			NTSTATUS status = pfnNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &dwProcessDebugPort, sizeof(dwProcessDebugPort), &dwReturned);
			if (NT_SUCCESS(status) && dwProcessDebugPort == -1) {
				return true;
			}
		}
	}
	return false;
}

/**
 * @brief Controlla se un byte specifico è presente in una determinata area di memoria.
 *
 * @param cByte Il byte da cercare.
 * @param pMemory Il puntatore all'area di memoria.
 * @param nMemorySize La dimensione dell'area di memoria (opzionale).
 * @return true se il byte è presente, altrimenti false.
 */
bool CheckForByte(BYTE cByte, PVOID pMemory, SIZE_T nMemorySize = 0) {
	PBYTE pBytes = (PBYTE)pMemory;
	for (SIZE_T i = 0; ; i++) {
		if (((nMemorySize > 0) && (i >= nMemorySize)) ||
			((nMemorySize == 0) && (pBytes[i] == 0xC3)))
			break;

		if (pBytes[i] == cByte)
			return true;
	}
	return false;
}

/**
 * @brief Controlla se un breakpoint è presente.
 *
 * @return true se un breakpoint è presente, altrimenti false.
 */
bool CheckForBreakpoint() {
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(CONTEXT));
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (!GetThreadContext(GetCurrentProcess(), &ctx)) {
		return false;
	}
	return ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0;
}

bool CheckForVM() {

	const char* vmVendors[] = {
		"VMware",
		"VirtualBox",
		"QEMU",
		"Xen",
		"KVM",
		"Virtual PC",
		"Hyper-V",
		"Bochs",
		"Parallels",
		"Bhyve",
		"Virtuozzo",
		"OpenVZ"
	};

	for (const char * vendor : vmVendors){
		if (GetModuleHandleA(vendor)) {
			return true;
		}
	}

	return false;
}
