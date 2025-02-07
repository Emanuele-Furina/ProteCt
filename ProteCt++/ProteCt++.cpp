// ProteCt++.cpp : Definisce le funzioni per la libreria statica.

#include "pch.h"
#include "framework.h"
#include <iostream>
#include "./ProteCt++.h"
#include <Windows.h>
#include <winternl.h>

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

bool CheckDebugFlagsEFLAGS() {
	DWORD dwFlags;
	__asm
	{
		pushfd
		pop eax
		mov dwFlags, eax // Ottiene i flag del registro EFLAGS (WIP)
	}
	if (dwFlags & 0x00010000) // se il bit 16 è settato allora c'è un debugger
	{
		return true;
	}
	else
	{
		return false;
	}
}


bool CheckDebugFlagsDR7() {
	DWORD dr7;
	__asm {
		mov eax, dr7
		mov dr7, eax
	}
	if (dr7 & 0x00000001) { // Controlla se il bit 0 è impostato, indicando un punto di interruzione hardware
		return true;
	}
	else {
		return false;
	}
}






