#include <Windows.h>
#include "winternl.h"
#include <stdio.h>
#include <psapi.h>

#ifdef _DEBUG
#define PICEDLL L"D:\\PICEv3Dbg.dll"
#else
#define PICEDLL L"PICEv3.dll"
#endif
#define NtCurrentProcess() ((HANDLE)-1)

//int stressTest(int counter);

/*EXTERN_C NTSTATUS NtCreateFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength);*/