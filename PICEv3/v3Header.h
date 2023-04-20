#pragma once
#include <Windows.h>


#define NtCurrentProcess() ((HANDLE)-1)
#define ProcessInstrumentationCallback (PROCESS_INFORMATION_CLASS)0x28 

typedef void(*CallbackFunction)();

typedef NTSTATUS(NTAPI* pNtSetInformationProcess)(
	HANDLE ProcessHandle,
	PROCESS_INFORMATION_CLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength
	);

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG Version; //0 for x86, 1 for x64
	ULONG Reserved; //Always 0
	CallbackFunction Callback; //Our hooking function
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;



// Below taken from syswhispers2 with modifications
#define RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)
#define ROL8(v) (v << 8 | v >> 24)
#define ROR8(v) (v >> 8 | v << 24)
#define ROX8(v) ((0xDEADBEEF % 2) ? ROL8(v) : ROR8(v))

typedef struct SYSCALL_ENTRY
{
	DWORD HashedName;	//Will be stored as a hash
	DWORD RVAAddress;	//Stored as RVA
} SYSCALL_ENTRY, * PSYSCALL_ENTRY;

typedef struct SYSCALL_LIST
{
	DWORD Count;
	SYSCALL_ENTRY Entries[500]; //We should never have more than 400ish
} SYSCALL_LIST, * PSYSCALL_LIST;