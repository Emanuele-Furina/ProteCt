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

#ifndef ThreadHideFromDebugger
#define ThreadHideFromDebugger (THREADINFOCLASS)0x11
#endif

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


bool IsLibraryLoaded() {
	return true;
}

/**
 * @brief Checks whether a debugger is present, using the IsDebuggerPresent API, this is usless as fuck
 *
 * @return true if a remote debugger is present, false otherwise.
 */
bool IsSimpleDebuggerPresent() {
	return IsDebuggerPresent();
}

/**
 * @brief Checks whether a remote debugger is present.
 *
 * @return true if a remote debugger is present, false otherwise.
 */
bool CheckRemoteDebugger() {
	BOOL bDebuggerPresent = FALSE;
	return CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent) && bDebuggerPresent;
}

/**
 * @brief Checks whether the process is debugged via the ProcessDebugPort.
 *
 * @return true if the process is debugged, false otherwise.
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
 * @brief Checks whether a specific byte is present in a specific memory area.
 *
 * @param cByte The byte to be searched for.
 * @param pMemory The pointer to the memory area.
 * @param nMemorySize The size of the memory area (optional).
 * @return true if the byte is present, false otherwise.
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
 * @brief Checks whether a breakpoint is present.
 *
 * @return true if a breakpoint is present, false otherwise.
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
 * @brief Checks whether the process is running in a virtual machine.
 *
 * This function checks for the presence of known virtual machine modules
 * such as VMware, VirtualBox, QEMU, Xen, KVM, Virtual PC, Hyper-V, Bochs, Parallels,
 * Bhyve, Virtuozzo and OpenVZ. If one of these modules is loaded, the function
 * returns true, indicating that the process is running in a virtual machine.
 *
 * @return true if the process is running in a virtual machine, otherwise false.
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
 * @brief Checks whether the process is being debugged using a memory page with guard protection.
 *
 * This function allocates a memory page, sets a return instruction (0xC3) to the page,
 * and then attempts to perform a jump to that page. If the jump causes an exception, it means that
 * there is no debugger present. If the jump does not cause an exception, it means that there is a debugger present.
 *

 *
 * @return true if the process is debugged, otherwise false.
 */
bool BreakDebugger() {
	SYSTEM_INFO SysInfo = { 0 };
	GetSystemInfo(&SysInfo);

	// Alloca una pagina di memoria eseguibile
	PVOID pPage = VirtualAlloc(NULL, SysInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pPage) {
		return false;
	}

	// Verifica che la memoria allocata sia sufficiente - FIX per il sovraccarico del buffer durante la scrittura
	if (SysInfo.dwPageSize < 2) {
		VirtualFree(pPage, 0, MEM_RELEASE);
		return false;
	}


	// Scrive istruzioni nella pagina per generare eccezioni controllate
	PBYTE pMem = static_cast<PBYTE>(pPage);
	pMem[0] = 0xCC; // Int 3 - Breakpoint software
	pMem[1] = 0xC3; // Ret - Ritorna dalla funzione

	// Protegge la memoria con PAGE_GUARD
	DWORD dwOldProtect = 0;
	if (!VirtualProtect(pPage, SysInfo.dwPageSize, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOldProtect)) {
		VirtualFree(pPage, 0, MEM_RELEASE);
		return false;
	}

	// Nasconde il thread corrente al debugger
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (hNtdll) {
		auto pfnNtSetInformationThread = reinterpret_cast<TNtSetInformationThread>(
			GetProcAddress(hNtdll, "NtSetInformationThread"));
		if (pfnNtSetInformationThread) {
			pfnNtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);
		}
	}

	bool exceptionOccurred = false;

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
		DWORD code = GetExceptionCode();
		if (code == EXCEPTION_GUARD_PAGE || code == EXCEPTION_BREAKPOINT) {
			exceptionOccurred = true;
		}
	}

	// Ripristina la protezione della memoria
	VirtualProtect(pPage, SysInfo.dwPageSize, dwOldProtect, &dwOldProtect);
	VirtualFree(pPage, 0, MEM_RELEASE);

	// Se l'eccezione non si � verificata, potrebbe essere presente un debugger
	return !exceptionOccurred;
}



/**
 * @brief Checks whether new modules have been loaded in the current process.
 *
 * This function uses the `EnumProcessModules` API to enumerate all modules loaded
 * in the current process. Modules are dynamic libraries (DLLs) that the process has loaded
 * in memory. The function maintains a static list of the initially loaded modules and * compares it with the current list of modules.
 * compares it with the current list of modules. If a new module is detected that was not
 * present in the initial list, the function returns true, indicating that a new module
 * has been loaded.
 *
 * @return true if new modules have been loaded, otherwise false.
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
