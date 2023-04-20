#include "v3Header.h"
#include <DbgHelp.h>
#include <stdio.h>
//#define SYMBOL_LOOKUP TRUE

#ifdef SYMBOL_LOOKUP
#pragma comment(lib,"Dbghelp.lib")
#endif


extern "C" VOID InstrumentationCallbackStub(VOID);
extern "C" VOID InstrumentationCallback(PCONTEXT ctx);

static ULONG_PTR g_NtdllBase;
static ULONG_PTR g_W32UBase;
static ULONG_PTR g_KernelBase;
static ULONG_PTR g_KernelBaseSize;
static DWORD g_NtdllSize;
static DWORD g_W32USize;
static SYSCALL_LIST g_List;
BOOLEAN NtdllConfirmed;
BOOLEAN W32UConfirmed;

pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll"),
	"NtSetInformationProcess");

const wchar_t* GetWC(const char* c)
{
	// https://stackoverflow.com/questions/8032080/how-to-convert-char-to-wchar-t
	const size_t cSize = strlen(c) + 1;
	wchar_t* wc = new wchar_t[cSize];
	mbstowcs(wc, c, cSize);

	return wc;
}

void DebugOut(const wchar_t* fmt, ...)
{
	//https://gist.github.com/syu5-gh/eaa0018ed70836b7279b
	va_list argp;
	va_start(argp, fmt);
	wchar_t dbg_out[4096];
	vswprintf_s(dbg_out, fmt, argp);
	va_end(argp);
	OutputDebugString(dbg_out);
}


DWORD GetSSN(SYSCALL_LIST List, ULONG_PTR ReturnAddress) //Verify FunctionPrologue matches the RVA
{
	for (DWORD i = 0; i < List.Count; i++)
	{
		if (ReturnAddress == RVA2VA(ULONG_PTR, g_NtdllBase, List.Entries[i].RVAAddress) + 0x14)
		{
			//wprintf(L"Return Address: 0x%016Ix\n", ReturnAddress);
			//wprintf(L"ZWReturnAddress: 0x%016Ix\n", RVA2VA(ULONG_PTR, g_NtdllBase, List.Entries[i].RVAAddress) + 0x14);
			return i;
		}
	}
	return -1;
}

/*VOID DiscoverProblem(ULONG_PTR ReturnAddress)
{
#pragma comment(lib,"Dbghelp.lib")
	SymSetOptions(SYMOPT_UNDNAME);
	SymInitialize(NtCurrentProcess(), NULL, TRUE);
	BOOLEAN SymbolLookupResult;
	DWORD64 Displacement;
	PSYMBOL_INFO SymbolInfo;
	PCHAR SymbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
	//Lookup and display the Symbol name if found for return address
	SymbolInfo = (PSYMBOL_INFO)SymbolBuffer; //Init SymbolBuffer
	RtlSecureZeroMemory(SymbolInfo, sizeof(SYMBOL_INFO) + MAX_SYM_NAME); //nukes the memory space for cleanliness
	SymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO); //Set Size to default
	SymbolInfo->MaxNameLen = 1024; //Set MaxNameLen to default

	//Check if we have symbols that correspond to the return address
	SymbolLookupResult = SymFromAddr(NtCurrentProcess(), (ULONG_PTR)ReturnAddress, &Displacement, SymbolInfo);
	if (SymbolLookupResult)
	{
		wprintf(L"SymFromAddr: [%s]\n", GetWC(SymbolInfo->Name));
	}
	else
	{
		wprintf(L"SymFromAddr: [NULL]\n");
	}
}
*/
DWORD HashSyscall(PCSTR FunctionName)
{
	DWORD i = 0;
	DWORD Hash = 0xDEADBEEF;	//Seed value for the function hash

	while (FunctionName[i])
	{
		WORD PartialName = *(WORD*)((ULONG64)FunctionName + i++);
		Hash ^= PartialName + ROR8(Hash);
	}

	return Hash;
}

VOID GetBaseAddresses() {

	PIMAGE_DOS_HEADER piDH;
	PIMAGE_NT_HEADERS piNH;

	g_NtdllBase = (ULONG_PTR)GetModuleHandleW(L"ntdll.dll");
	piDH = (PIMAGE_DOS_HEADER)g_NtdllBase;
	piNH = (PIMAGE_NT_HEADERS)(g_NtdllBase + piDH->e_lfanew);

	g_NtdllSize = piNH->OptionalHeader.SizeOfImage;

	g_W32UBase = (ULONG_PTR)GetModuleHandleW(L"win32u.dll");
	if (g_W32UBase) {
		piDH = (PIMAGE_DOS_HEADER)g_W32UBase;
		piNH = (PIMAGE_NT_HEADERS)(g_W32UBase + piDH->e_lfanew);
		g_W32USize = piNH->OptionalHeader.SizeOfImage;
	}
	g_KernelBase = (ULONG_PTR)GetModuleHandleW(L"kernelbase.dll");
	piDH = (PIMAGE_DOS_HEADER)g_KernelBase;
	piNH = (PIMAGE_NT_HEADERS)(g_KernelBase + piDH->e_lfanew);
	g_KernelBaseSize = piNH->OptionalHeader.SizeOfImage;
}

BOOLEAN CheckReturnAddressBounds(ULONG_PTR Rip, ULONG_PTR BaseAddress, DWORD ModuleSize)
{
	return (Rip > BaseAddress) && (Rip < (BaseAddress + ModuleSize));
}

VOID PopulateSysCallList()
{
	SYSCALL_LIST List = { 0, 1 };
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)g_NtdllBase;
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(g_NtdllBase + DosHeader->e_lfanew);

	PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeader->OptionalHeader.DataDirectory;
	DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;

	ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVA2VA(ULONG_PTR, g_NtdllBase, VirtualAddress);

	DWORD NumberOfNames = ExportDirectory->NumberOfNames;
	PDWORD Functions = RVA2VA(PDWORD, g_NtdllBase, ExportDirectory->AddressOfFunctions);
	PDWORD Names = RVA2VA(PDWORD, g_NtdllBase, ExportDirectory->AddressOfNames);
	PWORD Ordinals = RVA2VA(PWORD, g_NtdllBase, ExportDirectory->AddressOfNameOrdinals);


	DWORD i = 0;
	PSYSCALL_ENTRY Entries = List.Entries;


	// Populate SYSCALL_LIST with unzorted Zw * entries.
	do
	{
		PCHAR FunctionName = RVA2VA(PCHAR, g_NtdllBase, Names[NumberOfNames - 1]);
		// Is this a system call?
		if (*(USHORT*)FunctionName == 'wZ')
		{
			//printf("Found: %d)
			Entries[i].HashedName = HashSyscall(FunctionName);
			Entries[i].RVAAddress = Functions[Ordinals[NumberOfNames - 1]];
			i++;
			if (i == 500) break;
		}
	} while (--NumberOfNames);

	List.Count = i; // Save total number of calls found

	// Sort the list by address in ascending order
	for (i = 0; i < List.Count - 1; i++)
	{
		for (DWORD j = 0; j < List.Count - i - 1; j++)
		{
			if (Entries[j].RVAAddress > Entries[j + 1].RVAAddress) //If the address is bigger than the one next to it in the list
			{
				// Swap em!
				SYSCALL_ENTRY TempEntry;
				TempEntry.HashedName = Entries[j].HashedName;
				TempEntry.RVAAddress = Entries[j].RVAAddress;

				Entries[j].HashedName = Entries[j + 1].HashedName;
				Entries[j].RVAAddress = Entries[j + 1].RVAAddress;

				Entries[j + 1].HashedName = TempEntry.HashedName;
				Entries[j + 1].RVAAddress = TempEntry.RVAAddress;
			}
		}
	}
	g_List = List;
}

BOOLEAN CheckReturnFunctionSSN(ULONG_PTR ReturnAddress, ULONG_PTR ReturnSSN)
{

	DWORD LegitSSN = GetSSN(g_List, ReturnAddress); //Get the SSN that SHOULD be at the FunctionPrologue accordingly to NTDLL export table
	if ((DWORD)ReturnSSN == LegitSSN)
	{
		return TRUE;
	}
	return FALSE;
}

VOID InstrumentationCallback(PCONTEXT ctx)
{
	BOOLEAN bInstrumentationCallbackDisabled;
	ULONG_PTR NtdllBase;
	ULONG_PTR W32UBase;
	DWORD NtdllSize;
	DWORD W32USize;
	ULONG_PTR ReturnAddress;


	//Setup the necessary variables for debug output
#ifdef SYMBOL_LOOKUP
	BOOLEAN SymbolLookupResult;
	DWORD64 Displacement;
	PSYMBOL_INFO SymbolInfo;
	PCHAR SymbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
#endif
	//
	// https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/teb/index.htm
	//
	int cbDisableOffset = 0x02EC;	// TEB64->InstrumentationCallbackDisabled offset
	int instPrevPcOffset = 0x02D8;	// TEB64->InstrumentationCallbackPreviousPc offset
	int instPrevSpOffset = 0x02E0;  // TEB64->InstrumentationCallbackPreviousSp offset

	ULONG_PTR pTEB = (ULONG_PTR)NtCurrentTeb(); //Get the address of the TEB and store it for later
	//
	// Prevent recursion. TEB->InstrumentationCallbackDisabled
	//
	bInstrumentationCallbackDisabled = *((BOOLEAN*)pTEB + cbDisableOffset);

	/*
	In order to call RtlCaptureContext in our assembly code we use a few registers.  In order to preserve the values that originally existed there we placed those in the above thread save locations in the TEB.
	Our CONTEXT structure now contains a snapshot of registers that is ~almost~ correct, below we will fix the inconsistencies.
	*/
	//Originally R10
	//mov gs:[2d8h], r10
	//Contains the address in UM that the program would have returned to
	ctx->Rip = *((ULONG_PTR*)(pTEB + instPrevPcOffset)); // TEB->InstrumentationCallbackPreviousPc

	//Originally RSP
	//mov gs:[2e0h], rsp
	//Save the stack pointer in UM that the program needs to have when we resume
	ctx->Rsp = *((ULONG_PTR*)(pTEB + instPrevSpOffset)); // TEB->InstrumentationCallbackPreviousSp

	//Originally RCX
	//mov r10, rcx
	//Restoring the RCX value that was needed to perform the call to RtlCaptureContext
	ctx->Rcx = ctx->R10;

	//Resetting R10 to original value (same as RIP)
	ctx->R10 = ctx->Rip;



	//
	// Disabling for no recursion
	//Don't call any Win32 APIs before this
	*((BOOLEAN*)pTEB + cbDisableOffset) = TRUE; //set to 1
// Get pointers to DLL base addresss & sizes
	NtdllBase = g_NtdllBase;
	W32UBase = g_W32UBase;
	NtdllSize = g_NtdllSize;
	W32USize = g_W32USize;
	ReturnAddress = ctx->Rip;


#ifdef SYMBOL_LOOKUP
	//Lookup and display the Symbol name if found for return address
	SymbolInfo = (PSYMBOL_INFO)SymbolBuffer; //Init SymbolBuffer
	RtlSecureZeroMemory(SymbolInfo, sizeof(SYMBOL_INFO) + MAX_SYM_NAME); //nukes the memory space for cleanliness
	SymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO); //Set Size to default
	SymbolInfo->MaxNameLen = 1024; //Set MaxNameLen to default

	//Check if we have symbols that correspond to the return address
	SymbolLookupResult = SymFromAddr(NtCurrentProcess(), ReturnAddress, &Displacement, SymbolInfo);
#endif





	ULONG_PTR ReturnSSN = *((PULONG_PTR)(ReturnAddress - 0x10));
	//ULONG_PTR FunctionPrologue = *(PULONG_PTR)(ReturnAddress - 0x14);	//Offset to MOV R10, RCX

	NtdllConfirmed = CheckReturnAddressBounds(ctx->Rip, NtdllBase, NtdllSize);
	W32UConfirmed = CheckReturnAddressBounds(ctx->Rip, W32UBase, W32USize);

	if (NtdllBase && NtdllConfirmed) {
		if ((DWORD)ReturnSSN < 471) //471 Possible NT Functions, anything above this is random memory data we grabbed from UM Callbacks (IE: LdrInitializeThunk)
		{
#ifdef SYMBOL_LOOKUP
			LPCWSTR SymbolName = GetWC(SymbolInfo->Name) + 0x2; //Skip the first two Bytes to account for ZW
			if (!lstrcmpiW(SymbolName, SystemCallbySSN))
			{
				wprintf(L"[SSN-VERIFIED] NTDLL Symbol name using SymFromAddr: %s (0x%X)\n", GetWC(SymbolInfo->Name), ReturnSSN);
			}
			else {
				wprintf(L"Unverified: %s [%d] - %s [%d]\n", SymbolName, sizeof(SymbolName), SystemCallbySSN, sizeof(SystemCallbySSN));

			}
			//DebugOut(L"[+] NTDLL function name using SSN: %s (0x%X)\n",SystemCallbySSN, (DWORD)ReturnSSN);
#endif
			if (CheckReturnFunctionSSN(ReturnAddress, ReturnSSN))
			{
				ULONG_PTR ReturnSP = ctx->Rsp;
				ULONG_PTR KernelBase = g_KernelBase;
				DWORD KernelBaseSize = g_KernelBaseSize;
#ifdef _DEBUG
				wprintf(L"[+] NTDLL integrity verified. (%s)\n", SystemCallbySSN);
				//wprintf(L"Return SP: 0x%016Ix\n", ReturnSP);
#endif
				NtdllConfirmed = CheckReturnAddressBounds(*(PULONG_PTR)ReturnSP, NtdllBase, NtdllSize);
				W32UConfirmed = CheckReturnAddressBounds(*(PULONG_PTR)ReturnSP, W32UBase, W32USize);
				ULONG_PTR KernelBaseConfirmed = CheckReturnAddressBounds(*(PULONG_PTR)ReturnSP, KernelBase, KernelBaseSize);

				if (KernelBaseConfirmed || NtdllConfirmed || W32UConfirmed)
				{
#ifdef _DEBUG
					wprintf(L"[+] Stack integrity verified.\n");
#endif
				}
				else
				{

					wprintf(L"[-] Stack modification detected. Terminating execution.\n");
					//DebugBreak();
					ExitProcess(ERROR_INVALID_ACCESS);
				}
				
				//DiscoverProblem(*(PULONG_PTR)ReturnSP);
	
			}
			else
			{
				wprintf(L"[-] NTDLL Function Prologue mismatch. Possible SSN tampering\n");

				ExitProcess(ERROR_INVALID_ACCESS);
				//wprintf(L"[!] Actual Function Prologue:  0x%016Ix\n", FunctionPrologue);
			}
		}
		else
		{
			//
			//UM Callback Detected: LdrInitializeThunk, KiUserCallBackDispatcher, KiUserAPCDispatcher, etc...
			//
			//DebugOut(L"[+] NTDLL Symbol name using SymFromAddr: %s \n", GetWC(SymbolInfo->Name));
			//wprintf(L"Invalid SSN detected. Most likely as UM callback.\n");
		}


	}
	else if (W32UBase && W32UConfirmed) { // W32UBase will only return true if it has been loaded into memory already
#ifdef _DEBUG
		//DebugOut(L"[+] W32U Symbol name: %s (0x%X)\n", GetWC(SymbolInfo->Name), ReturnSSN);
		//wprintf(L"[+] W32U SSN: 0x%X\n", ReturnSSN);
#endif
	}
	else {
		//
		// If Module fails to verify to a known address
		//
#ifdef _DEBUG
			//wprintf(L"[I] ReturnAddress: 0x%016Ix\n", ReturnAddress);
		wprintf(L"[!] Kernel returns to unverified module location [0x%016Ix]\n", ReturnAddress);
		//DiscoverProblem(ReturnAddress);
		//wprintf(L"[I] CTX->Rip: 0x%016Ix\n", ctx->Rip);
		//wprintf(L"[I] ReturnSSN: 0x%016Ix\n", ReturnSSN);

		wprintf(L"[!] Preventing further execution!\n"); //Process deemed malicious. Terminate execution.
#endif
		//DebugOut(L"Unverified Module\n");
		ExitProcess(ERROR_INVALID_ACCESS);
	}
	*((BOOLEAN*)pTEB + cbDisableOffset) = FALSE; //Enabling so we can catch next callback.

	RtlRestoreContext(ctx, NULL);	 //Restore registers and resume execution

}


int sethook(bool Enable)
{

	if (Enable)
	{
		//
		// Obtain ntdll and optionally w32u.dll's base address 
		//
		GetBaseAddresses();
		//
		// Obtain all the exported NT* System Calls from ntdll.dll and store them in custom struct
		//
		PopulateSysCallList();
#ifdef _DEBUG
#ifdef SYMBOL_LOOKUP
		SymSetOptions(SYMOPT_UNDNAME);
		SymInitialize(NtCurrentProcess(), NULL, TRUE);
#endif
		//AllocConsole();
		//freopen("CONOUT$", "w", stdout);

		wprintf(L"[+] Logging started...\n");
		wprintf(L"[+] ntdll BaseAddress: 0x%016Ix\n", g_NtdllBase);
		wprintf(L"[+] win32u BaseAddress: 0x%016Ix\n", g_W32UBase);
		wprintf(L"[+] kernelbase BaseAddress: 0x%016Ix\n", g_KernelBase);
		wprintf(L"[d] Calling NtSetInformationProcess() to ENABLE hook\n");
#endif
	}
	else
	{
#ifdef _DEBUG
		wprintf(L"[d] Calling NtSetInformationProcess() to DISABLE hook\n");
		//DebugOut(L"[d] Calling NtSetInformationProcess() to DISABLE hook\n");
#endif
	}

	CallbackFunction InstrumentationCallbackStatus = Enable ? InstrumentationCallbackStub : NULL; //Determines whether we are placing or removing a hook

	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION PICInfo;
	PICInfo.Callback = InstrumentationCallbackStatus; //Enabled = contains address, Disabled = NULL
	PICInfo.Reserved = 0;
	PICInfo.Version = 0;

	//Request EPROCESS structure alter the PIC field and substitute with our callback address
	return NtSetInformationProcess(NtCurrentProcess(), ProcessInstrumentationCallback, &PICInfo, sizeof(PICInfo));

}
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		sethook(TRUE);
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		sethook(FALSE);
		break;

	case DLL_PROCESS_DETACH:
		sethook(FALSE);
		break;
	}
	// Return true or the DLL will unload/cause process to exit.
	return TRUE;
}