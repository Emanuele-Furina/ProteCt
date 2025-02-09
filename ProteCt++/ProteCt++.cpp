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
#include <stdio.h>
#include <psapi.h>


typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
	IN HANDLE           ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID           ProcessInformation,
	IN ULONG            ProcessInformationLength,
	OUT PULONG          ReturnLength
);

typedef NTSTATUS(NTAPI* TNtSetInformationThread)(
	HANDLE ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength
);

constexpr size_t SHA256_HASH_SIZE = 32;
constexpr size_t BUFFER_SIZE = 4096;

bool IsLibraryLoaded() {
	return true;
}

/**
 * @brief Classe RAII per gestire automaticamente l'handle del file.
 */
class FileHandle {
public:
	explicit FileHandle(HANDLE handle) : handle_(handle) {}
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

bool IsSimpleDebuggerPresent() {
	return IsDebuggerPresent();
}

/**
 * @brief Controlla se un debugger remoto è presente.
 *
 * @return true se un debugger remoto è presente, altrimenti false.
 */
bool CheckRemoteDebugger() {
	BOOL bDebuggerPresent = FALSE;
	return CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent) && bDebuggerPresent;
}

/**
 * @brief Controlla se il processo è in debug tramite il ProcessDebugPort.
 *
 * @return true se il processo è in debug, altrimenti false.
 */
bool CheckProcessDebugPort() {
	/* HMODULE hNtdll = LoadLibraryA("ntdll.dll");  Uso GetModuleHandleA per evitare di ricaricare la libreria e fare interferenza con CheckForNewModules()  */
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (hNtdll) {
		auto pfnNtQueryInformationProcess = reinterpret_cast<TNtQueryInformationProcess>(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
		if (pfnNtQueryInformationProcess) {
			DWORD dwProcessDebugPort = 0;
			ULONG dwReturned = 0;
			NTSTATUS status = pfnNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &dwProcessDebugPort, sizeof(dwProcessDebugPort), &dwReturned);
			FreeLibrary(hNtdll);
			return NT_SUCCESS(status) && dwProcessDebugPort == -1;
		}
		FreeLibrary(hNtdll);
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
	PBYTE pBytes = static_cast<PBYTE>(pMemory);
	for (SIZE_T i = 0; ; i++) {
		if ((nMemorySize > 0 && i >= nMemorySize) || (nMemorySize == 0 && pBytes[i] == 0xC3)) {
			break;
		}
		if (pBytes[i] == cByte) {
			return true;
		}
	}
	return false;
}

/**
 * @brief Controlla se un breakpoint è presente.
 *
 * @return true se un breakpoint è presente, altrimenti false.
 */
bool CheckForBreakpoint() {
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (!GetThreadContext(GetCurrentThread(), &ctx)) {
		return false;
	}
	return ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0;
}

/**
 * @brief Verifica se il processo è in esecuzione in una macchina virtuale.
 *
 * Questa funzione controlla la presenza di moduli noti di macchine virtuali
 * come VMware, VirtualBox, QEMU, Xen, KVM, Virtual PC, Hyper-V, Bochs, Parallels,
 * Bhyve, Virtuozzo e OpenVZ. Se uno di questi moduli è caricato, la funzione
 * restituisce true, indicando che il processo è in esecuzione in una macchina virtuale.
 *
 * @return true se il processo è in esecuzione in una macchina virtuale, altrimenti false.
 */
bool CheckForVM() {
	const char* vmVendors[] = {
		"VMware", "VirtualBox", "QEMU", "Xen", "KVM", "Virtual PC", "Hyper-V",
		"Bochs", "Parallels", "Bhyve", "Virtuozzo", "OpenVZ"
	};

	for (const char* vendor : vmVendors) {
		if (GetModuleHandleA(vendor)) {
			return true;
		}
	}
	return false;
}

/**
 * @brief Verifica se il processo è in debug utilizzando una pagina di memoria con protezione di guardia.
 *
 * Questa funzione alloca una pagina di memoria, imposta un'istruzione di ritorno (0xC3) nella pagina,
 * e poi tenta di eseguire un salto a quella pagina. Se il salto causa un'eccezione, significa che
 * non c'è un debugger presente. Se il salto non causa un'eccezione, significa che c'è un debugger presente.
 * 
 * Non so cosa altro inventarmi se lo bypassano sono dei cazzo di maghi.
 *
 * @return true se il processo è in debug, altrimenti false.
 */
bool IsMemoryBreakpoints() {
	SYSTEM_INFO SysInfo = { 0 };
	GetSystemInfo(&SysInfo);

	// Nasconde il thread dal debugger
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (hNtdll) {
		auto pfnNtSetInformationThread = reinterpret_cast<TNtSetInformationThread>(
			GetProcAddress(hNtdll, "NtSetInformationThread")
			);
		if (pfnNtSetInformationThread) {
			pfnNtSetInformationThread(GetCurrentThread(), (THREADINFOCLASS)0x11, NULL, 0);
		}
	}

	// Alloca una pagina di memoria eseguibile
	PVOID pPage = VirtualAlloc(NULL, SysInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pPage) {
		return false;
	}

	PBYTE pMem = static_cast<PBYTE>(pPage);
	*pMem = 0xC3;  // Istruzione "RET" per terminare la funzione in modo sicuro

	// Protegge la memoria con il flag PAGE_GUARD
	DWORD dwOldProtect = 0;
	if (!VirtualProtect(pPage, SysInfo.dwPageSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &dwOldProtect)) {
		VirtualFree(pPage, 0, MEM_RELEASE);
		return false;
	}

	bool debuggerDetected = false;

	__try {
#ifdef _M_IX86
		__asm {
			mov eax, pPage
			jmp eax
		}
#elif defined(_M_X64)
		auto func = reinterpret_cast<void(*)()>(pPage);
		func();
#endif
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		debuggerDetected = true;
	}

	VirtualFree(pPage, 0, MEM_RELEASE);
	return debuggerDetected;
}

/**
 * @brief Controlla se nuovi moduli sono stati caricati nel processo corrente.
 *
 * Questa funzione utilizza l'API `EnumProcessModules` per enumerare tutti i moduli caricati
 * nel processo corrente. I moduli sono librerie dinamiche (DLL) che il processo ha caricato
 * in memoria. La funzione mantiene una lista statica dei moduli caricati inizialmente e la
 * confronta con la lista corrente dei moduli. Se viene rilevato un nuovo modulo che non era
 * presente nella lista iniziale, la funzione restituisce true, indicando che un nuovo modulo
 * è stato caricato.
 *
 * @return true se nuovi moduli sono stati caricati, altrimenti false.
 */
bool CheckForNewModules() {
	static std::vector<HMODULE> loadedModules;

	DWORD cbNeeded = 0;
	HMODULE hModules[1024];
	HANDLE hProcess = GetCurrentProcess();

	if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
		size_t moduleCount = cbNeeded / sizeof(HMODULE);
		if (loadedModules.empty()) {
			loadedModules.assign(hModules, hModules + moduleCount);
			return false;
		}

		for (size_t i = 0; i < moduleCount; ++i) {
			if (std::find(loadedModules.begin(), loadedModules.end(), hModules[i]) == loadedModules.end()) {
				loadedModules.assign(hModules, hModules + moduleCount);
				return true;
			}
		}
	}

	return false;
}
