// ProteCt++.cpp : Definisce le funzioni per la libreria statica.

#include "pch.h"
#include "framework.h"
#include <iostream>
#include "./ProteCt++.h"
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
	IN HANDLE           ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID           ProcessInformation,
	IN ULONG            ProcessInformationLength,
	OUT PULONG          ReturnLength
);


bool IsLibraryLoaded() {

	return true;
}

bool IsSimpleDebuggerPresent() {

	if (IsDebuggerPresent())
	{
		return true;
	}
	else
	{
		return false;
	}
}


bool CheckRemoteDebugger() {

	BOOL bDebuggerPresent;
	if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent) && TRUE == bDebuggerPresent) {
	
		return true;
	}
	else {
		return false;
	}
}



bool CheckProcessDebugPort() {
	HMODULE hNtdll = LoadLibraryA("ntdll.dll"); // Carica la libreria ntdll.dll
	if (hNtdll)
	{
		auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess"); // Ottiene l'indirizzo della funzione NtQueryInformationProcess
		if (pfnNtQueryInformationProcess)
		{
			DWORD dwProcessDebugPort, dwReturned;
			NTSTATUS status = pfnNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &dwProcessDebugPort, sizeof(dwProcessDebugPort), &dwReturned); // Ottiene il valore del ProcessDebugPort
			if (NT_SUCCESS(status) && (-1 == dwProcessDebugPort))
			{
				return true; // Il processso è in debug
			}
		}
	}
	else
	{
		return false;
	}
}

// Funzione per controllare se un byte è presente in una determinata area di memoria (è veramente utile?)
bool CheckForByte(BYTE cByte, PVOID pMemory, SIZE_T nMemorySize = 0) {
	PBYTE pBytes = (PBYTE)pMemory;
	for (SIZE_T i = 0; ; i++)
	{
		
		if (((nMemorySize > 0) && (i >= nMemorySize)) ||
			((nMemorySize == 0) && (pBytes[i] == 0xC3)))
			break;

		if (pBytes[i] == cByte)
			return true;
	}
	return false;
}

// Funzione per controllare se un breakpoint è presente
bool CheckForBreakpoint() {
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(CONTEXT));
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (!GetThreadContext(GetCurrentProcess(), &ctx))
	{
		return false;
	}
	else if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) //da vedere se funge ref: https://anti-debug.checkpoint.com/techniques/process-memory.html#software-breakpoints
	{
		return true;
	}
}




