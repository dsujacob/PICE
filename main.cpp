#include <Windows.h>
#include <DbgHelp.h>
#include <stdio.h>
//
//Many of these functions are modified versions, building off of previous works. Credit to the original authors: Jack Ullrich, Conor Richard, MDSEC, and of course Alex Ionescu for originally discovering PIC
// This version specifically contains minimal edits as detailed in the paper.
// 
//#define SUPERDEBUG TRUE
#pragma comment(lib,"Dbghelp.lib")

extern "C" VOID InstrumentationCallbackThunk(VOID);
extern "C" VOID InstrumentationCallback(PCONTEXT ctx);

#define RIP_SANITY_CHECK(Rip,BaseAddress,ModuleSize) (Rip > BaseAddress) && (Rip < (BaseAddress + ModuleSize))
#define NtCurrentProcess() ((HANDLE)-1)
#define ProcessInstrumentationCallback (PROCESS_INFORMATION_CLASS)0x28

static ULONG_PTR g_NtdllBase;
static ULONG_PTR g_W32UBase;
static DWORD g_NtdllSize;
static DWORD g_W32USize;
BOOLEAN NtdllConfirmed;
BOOLEAN W32UConfirmed;


typedef void(*CallbackFunction)();
typedef NTSTATUS(NTAPI* pNtSetInformationProcess)(
	HANDLE ProcessHandle,
	PROCESS_INFORMATION_CLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength
	);

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG Version;
	ULONG Reserved;
	CallbackFunction Callback; //Our hooking function
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll"),
	"NtSetInformationProcess");

// https://stackoverflow.com/questions/8032080/how-to-convert-char-to-wchar-t
const wchar_t* GetWC(const char* c)
{
	const size_t cSize = strlen(c) + 1;
	wchar_t* wc = new wchar_t[cSize];
	mbstowcs(wc, c, cSize);

	return wc;
}

//https://gist.github.com/syu5-gh/eaa0018ed70836b7279b
void DebugOut(const wchar_t* fmt, ...)
{
	va_list argp;
	va_start(argp, fmt);
	wchar_t dbg_out[4096];
	vswprintf_s(dbg_out, fmt, argp);
	va_end(argp);
	OutputDebugString(dbg_out);
}


VOID GetBaseAddresses() {

	PIMAGE_DOS_HEADER piDH;
	PIMAGE_NT_HEADERS piNH;

	g_NtdllBase = (ULONG_PTR)GetModuleHandle(TEXT("ntdll.dll"));
	piDH = (PIMAGE_DOS_HEADER)g_NtdllBase;
	piNH = (PIMAGE_NT_HEADERS)(g_NtdllBase + piDH->e_lfanew);

	g_NtdllSize = piNH->OptionalHeader.SizeOfImage;

	g_W32UBase = (ULONG_PTR)GetModuleHandle(TEXT("win32u.dll"));
	if (g_W32UBase) {
		piDH = (PIMAGE_DOS_HEADER)g_W32UBase;
		piNH = (PIMAGE_NT_HEADERS)(g_W32UBase + piDH->e_lfanew);
		g_W32USize = piNH->OptionalHeader.SizeOfImage;
	}
}

VOID InstrumentationCallback(PCONTEXT ctx)
{
	BOOLEAN bInstrumentationCallbackDisabled;
	ULONG_PTR NtdllBase;
	ULONG_PTR W32UBase;
	DWORD NtdllSize;
	DWORD W32USize;
	uintptr_t ReturnAddress, ReturnVal;

	//Setup the necessary variables for debug output
	BOOLEAN SymbolLookupResult;
	DWORD64 Displacement;
	PSYMBOL_INFO SymbolInfo;
	PCHAR SymbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];

	ULONG_PTR pTEB = (ULONG_PTR)NtCurrentTeb(); //Get the address of the TEB and store it for later

	//
	// https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/teb/index.htm
	//
	int cbDisableOffset = 0x02EC;	// TEB64->InstrumentationCallbackDisabled offset
	int instPrevPcOffset = 0x02D8;	// TEB64->InstrumentationCallbackPreviousPc offset
	int instPrevSpOffset = 0x02E0;  // TEB64->InstrumentationCallbackPreviousSp offset

	//In order to call RtlCaptureContext in our assembly code we use a few registers.  In order to preserve the values that originally existed there we placed those in the above thread save locations in the TEB.
	//Our CONTEXT structure now contains a snapshot of registers that is ~almost~ correct, below we will fix the inconsistencies.

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
	// Prevent recursion. TEB->InstrumentationCallbackDisabled
	//
	bInstrumentationCallbackDisabled = *((BOOLEAN*)pTEB + cbDisableOffset);

	if (!bInstrumentationCallbackDisabled) { //If offset is 0

		//
		// Disabling for no recursion
		//Don't call any Win32 APIs before this
		*((BOOLEAN*)pTEB + cbDisableOffset) = TRUE; //set to 1

		//Lookup and display the Symbol name if found for return address
		SymbolInfo = (PSYMBOL_INFO)SymbolBuffer; //Init SymbolBuffer
		RtlSecureZeroMemory(SymbolInfo, sizeof(SYMBOL_INFO) + MAX_SYM_NAME); //nukes the memory space for cleanliness
		SymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO); //Set Size to default
		SymbolInfo->MaxNameLen = 1024; //Set MaxNameLen to default

		//Check if we have symbols that correspond to the return address
		ReturnAddress = ctx->Rip;
		SymbolLookupResult = SymFromAddr(NtCurrentProcess(), ReturnAddress, &Displacement, SymbolInfo);

		if (SymbolLookupResult) {
#ifdef SUPERDEBUG
			DebugOut(L"################################################\n");
#endif
#ifdef _DEBUG
			DebugOut(L"[+] Symbol name: %s\n", GetWC(SymbolInfo->Name));
#endif
#ifdef SUPERDEBUG
			//DebugOut(L"[d] CTX->Rip: 0x%016Ix\n", ctx->Rip);
			DebugOut(L"[d] ReturnAddress: 0x%016Ix\n", ReturnAddress);
			//DebugBreak();
#endif
			//DebugOut(L"[d] ReturnVal: 0x%016Ix\n", ReturnVal);
			/*
				ULONG_PTR NtdllBase;
				ULONG_PTR W32UBase;
				DWORD NtdllSize;
				DWORD W32USize;
			*/

			// Get pointers to DLL base addresss & sizes
			//Basically fancy ways to get pointers from addresses


			NtdllBase = (ULONG_PTR)InterlockedCompareExchangePointer(
				(PVOID*)&g_NtdllBase,
				NULL,
				NULL
			);

			W32UBase = (ULONG_PTR)InterlockedCompareExchangePointer(
				(PVOID*)&g_W32UBase,
				NULL,
				NULL
			);
			NtdllSize = InterlockedCompareExchange(
				(DWORD*)&g_NtdllSize,
				NULL,
				NULL
			);

			W32USize = InterlockedCompareExchange(
				(DWORD*)&g_W32USize,
				NULL,
				NULL
			);
	
			NtdllConfirmed = RIP_SANITY_CHECK(ctx->Rip, NtdllBase, NtdllSize);
			W32UConfirmed = RIP_SANITY_CHECK(ctx->Rip, W32UBase, W32USize);

			if (NtdllBase && NtdllConfirmed) {
#ifdef SUPERDEBUG
				//
				// See if we can look up by name
				//Reverse lookup as opposed to simply getting the symbols for the return address
				

				PVOID pFunction = GetProcAddress((HMODULE)NtdllBase, SymbolInfo->Name);
				if (!pFunction) {
					DebugOut(L"[-] Reverse lookup failed for function: %s.\n", GetWC(SymbolInfo->Name));
				}
				else {
					DebugOut(L"[+] Reverse lookup successful for function %s.\n", GetWC(SymbolInfo->Name));
				}
#endif
			}
			/*else {

				DebugOut(L"[-] ntdll.dll not found.\n"); //In theory should never print because it's always loaded into processes by default
			}*/


			// W32UBase will only return true if it has been loaded into memory already
			else if (W32UBase && W32UConfirmed) {
				//
				// See if we can look up by name
				//
				//Honestly This doesn't add any extra scrutiny to the verification process. Remove in future versions.
				PVOID pFunction = GetProcAddress((HMODULE)W32UBase, SymbolInfo->Name);
#ifdef _DEBUG
				if (!pFunction) {
					DebugOut(L"[-] Reverse lookup failed for function: %s.\n", GetWC(SymbolInfo->Name));
				}
				else {
					DebugOut(L"[+] Reverse lookup successful for function %s.\n", GetWC(SymbolInfo->Name));
				}
#endif

			}
			/*else {
				DebugOut(L"[-] win32u.dll not found.\n"); //Wouldn't this constantly print if it's not being used?
			}*/
			else {
				//
				// If Module fails to verify to a known address
				//
#ifdef _DEBUG
				DebugOut(L"[I] ReturnAddress: 0x%016Ix\n", ReturnAddress);
				DebugOut(L"[!] Kernel returns to unverified module.\n");
				//DebugOut(L"[I] CTX->Rip: 0x%016Ix\n", ctx->Rip);
				//DebugOut(L"[I] ReturnVal: 0x%016Ix\n", ReturnVal);

				DebugOut(L"[!] Preventing further execution!\n"); //Process deemed malicious. Terminate execution.
#endif
				//DebugBreak();
				ExitProcess(ERROR_INVALID_ACCESS);
			}
		}
		else {

			//
			// SymFromAddr failed
			//
#ifdef _DEBUG
			DebugOut(L"[-] SymAddr Failed\n");
			DebugOut(L"[d] CTX->Rip: 0x%016Ix\n", ctx->Rip);
#endif
		}
		//
		// Enabling so we can catch next callback.
		//
		*((BOOLEAN*)pTEB + cbDisableOffset) = FALSE; //Set to 0
	}
	RtlRestoreContext(ctx, NULL);	 //Restore registers and resume execution
}


int sethook(bool Enable)
{
	CallbackFunction Thunk = Enable ? InstrumentationCallbackThunk : NULL; //Determines whether we are placing or removing a hook
	//
	// Obtain ntdll and optionally w32u.dll's base address 
	//
	GetBaseAddresses();

	LoadLibraryA("dbghelp.dll");
	SymSetOptions(SYMOPT_UNDNAME);
	SymInitialize(GetCurrentProcess(), NULL, TRUE);

	//AllocConsole();
	//freopen("CONOUT$", "w", stdout);

#ifdef _DEBUG
	if (Enable)
	{
		DebugOut(L"[+] Logging started...\n");
		DebugOut(L"[+] ntdll BaseAddress: 0x%016Ix\n", g_NtdllBase);
		DebugOut(L"[+] win32u BaseAddress: 0x%016Ix\n", g_W32UBase);
		DebugOut(L"[d] Calling NtSetInformationProcess() to ENABLE hook\n");
	}
	else
	{
		DebugOut(L"[d] Calling NtSetInformationProcess() to DISABLE hook\n");
	}
#endif
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION PICInfo;
	PICInfo.Callback = Thunk; //(PVOID)(ULONG_PTR)InstrumentationCallbackThunk;
	PICInfo.Reserved = 0;
	PICInfo.Version = 0;
	
	/*HANDLE hProcessHandle;
	hProcessHandle = OpenProcess(PROCESS_SET_INFORMATION, FALSE, 5012);

	if (!hProcessHandle)
	{
		DebugOut(L"Handle Error: <%lu>\n", GetLastError());
	}*/
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