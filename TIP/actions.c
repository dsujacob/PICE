#pragma once
#include "tipheader.h"


int stressTest(int COUNTER)
{
	NTSTATUS status = NULL;
	UNICODE_STRING fileName;
	int i;
	UNICODE_STRING baseString;
	RtlInitUnicodeString(&baseString, L"C:\\file");

	//CreateFile Loop
	for (i = 1; i <= COUNTER; i++)
	{
		wchar_t buffer[128];
		swprintf(buffer, 128, L"%ls%d", baseString.Buffer, i); //baseString + i
#ifdef _DEBUG
		wprintf(L"Creating %ls...\n", buffer);
#endif
		RtlInitUnicodeString(&fileName, buffer);

		//Using the WinAPI instead
		HANDLE hFile = CreateFileW(fileName.Buffer, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL); //NtCreateFile
		CloseHandle(hFile); //NtClose
	}

	//WriteFile Loop
	PCWSTR Message = L"HelloWorld!";
	DWORD dwBytesToWrite = wcslen(Message) * sizeof(wchar_t); //Two bytes per unicode char
	for (i = 1; i <= COUNTER; i++)
	{
		DWORD bytesWritten;
		wchar_t buffer[128];
		swprintf(buffer, 128, L"%ls%d", baseString.Buffer, i); //baseString + i
#ifdef _DEBUG
		wprintf(L"Writing to %ls...\n", buffer);
#endif
		RtlInitUnicodeString(&fileName, buffer);
		HANDLE hFile = CreateFileW(fileName.Buffer, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); //Have to call this again in order to get a file handle
		if (hFile != INVALID_HANDLE_VALUE)
		{
			if (!WriteFile(hFile, Message, dwBytesToWrite, &bytesWritten, NULL))//NtCreateFile
			{
				//wprintf(L"Error\n");
				wprintf(L"Error: %u\n", GetLastError());
			}
		}
		else
		{
			wprintf(L"Failed to open handle to %ls\n", fileName.Buffer);
			wprintf(L"Error: %u\n", GetLastError());
		}
		CloseHandle(hFile); //NtClose
	}

	//ReadFile loop
	for (i = 1; i <= COUNTER; i++)
	{
		DWORD bytesWritten;
		wchar_t buffer[128];
		wchar_t readBuffer[50] = { '\0' };
		swprintf(buffer, 128, L"%ls%d", baseString.Buffer, i); //baseString + i
#ifdef _DEBUG
		wprintf(L"Reading from %ls...\n", buffer);
#endif
		RtlInitUnicodeString(&fileName, buffer);
		HANDLE hFile = CreateFileW(fileName.Buffer, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); //Have to call this again in order to get a file handle
		if (hFile != INVALID_HANDLE_VALUE)
		{
			if (!ReadFile(hFile, &readBuffer, dwBytesToWrite, &bytesWritten, NULL)) //NtCreateFile
			{
				wprintf(L"Error: %u\n", GetLastError());
			}
			else
			{
#ifdef _DEBUG
				wprintf(L"Read: %ls\n", readBuffer);
#endif
			}
		}
		else
		{
			wprintf(L"Failed to open handle to %ls\n", fileName.Buffer);
			wprintf(L"Error: %u\n", GetLastError());
		}

		CloseHandle(hFile); //NtClose
	}

	//DeleteFile loop
	for (i = 1; i <= COUNTER; i++)
	{
		wchar_t buffer[128];
		swprintf(buffer, 128, L"%ls%d", baseString.Buffer, i); //baseString + i
		RtlInitUnicodeString(&fileName, buffer);

		if (!DeleteFileW(fileName.Buffer)) //NtCreateFile
		{
			wprintf(L"Error: %u\n", GetLastError());
		}
#ifdef _DEBUG
		else
		{
			wprintf(L"Deleted %ls\n", fileName.Buffer);
		}
#endif
	}
	return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// 
// Everything below are extra functions that were written during development to augment analysis.
// 
///////////////////////////////////////////////////////////////////////////////////////////////////


//
//Create a single file on disk using the WinAPI properly.
//
int justmakefile()
{
	UNICODE_STRING baseString;
	RtlInitUnicodeString(&baseString, L"C:\\deleteme");

	HANDLE hFile = CreateFileW(baseString.Buffer, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL); //Eventually will NtCreateFile

	CloseHandle(hFile); //Will eventually call NtClose
	return 0;
}

//
// Disables PICE removing it from the EPROCESS structure.
//
extern int disablePICE()
{
#define ProcessInstrumentationCallback (PROCESS_INFORMATION_CLASS)0x28

	typedef NTSTATUS(NTAPI* pNtSetInformationProcess)(
		HANDLE ProcessHandle,
		PROCESS_INFORMATION_CLASS ProcessInformationClass,
		PVOID ProcessInformation,
		ULONG ProcessInformationLength
		);
	typedef void(*CallbackFunction)();
	typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
	{
		ULONG Version;
		ULONG Reserved;
		CallbackFunction Callback; //Our hooking function
	} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

	pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll"),
		"NtSetInformationProcess");
	wprintf(L"KILLING HOOK\n");
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION PICInfo;
	PICInfo.Callback = NULL;
	PICInfo.Reserved = 0;
	PICInfo.Version = 0;
	//HANDLE hValue = 0xffffffffffffffff;
	return NtSetInformationProcess((HANDLE)0xffffffffffffffff, ProcessInstrumentationCallback, &PICInfo, sizeof(PICInfo));
}

//
// Using the WINAPI, retrieve the current computer's name and print it to the screen.
//
int getname()
{
	wchar_t lpBuffer[sizeof(MAX_COMPUTERNAME_LENGTH + 1)];
	DWORD nSize = MAX_COMPUTERNAME_LENGTH + 1;
	if (GetComputerNameW(lpBuffer, &nSize))
	{
		wprintf(L"%s\n", lpBuffer);
	}
	else {
		wprintf(L"Error: %lu\n", GetLastError());
	}
	return 1;
}

//
// Outputs TIP results to a file in CSV format instead of printing to screen. Never worked reliably.
//
int writeOutput(ULONG_PTR ElaspedWallTime,
	ULONG_PTR totalCPUUserTime,
	ULONG_PTR totalCPUKernelTime,
	ULONG_PTR PeakPagefileUsage,
	ULONG_PTR PeakWorkingSetSize)
{
	UNICODE_STRING tipResults;
	UNICODE_STRING fileName;
	wchar_t* nameBuffer = L"D:\\blastzone\\tipResults.txt";
	RtlInitUnicodeString(&fileName, nameBuffer);
	DWORD dwSize = sizeof(ElaspedWallTime) + sizeof(totalCPUUserTime) + sizeof(totalCPUKernelTime) + sizeof(PeakPagefileUsage) + sizeof(PeakWorkingSetSize);
	wchar_t outputBuffer[sizeof(ULONG_PTR)*6];
	swprintf(outputBuffer, dwSize, L"%I64d,%I64d,%I64d,%I64d,%I64d\r\n", ElaspedWallTime, totalCPUUserTime, totalCPUKernelTime, PeakPagefileUsage, PeakWorkingSetSize); 

	HANDLE hFile = CreateFileW(fileName.Buffer, FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); //Have to call this again in order to get a file handle
	if (hFile != INVALID_HANDLE_VALUE)
	{
		DWORD dwBytesToWrite = ((lstrlenW(outputBuffer)) * sizeof(wchar_t))+2;
		DWORD bytesWritten;
		if (!WriteFile(hFile, outputBuffer, dwBytesToWrite, &bytesWritten, NULL))//NtCreateFile
		{
			//wprintf(L"Error\n");
			wprintf(L"Error: %u\n", GetLastError());
		}
	}
	else
	{
		wprintf(L"Failed to open handle to %ls\n", fileName.Buffer);
		wprintf(L"Error: %u\n", GetLastError());
	}
	CloseHandle(hFile); //NtClose
}

//
//Example function that creates a file using a manual system call
//
int executeManualSystemCall()
{
	UNICODE_STRING fileName;
	IO_STATUS_BLOCK osb;
	OBJECT_ATTRIBUTES oa;
	HANDLE fileHandle = NULL;
	ZeroMemory(&osb, sizeof(IO_STATUS_BLOCK));

	RtlInitUnicodeString(&fileName, (PCWSTR)L"\\??\\C:\\blastzone\\maliciousfile.txt");
	InitializeObjectAttributes(&oa, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	//
	// Initiate manual system call (should be considered malicious)
	//
	NtCreateFile(
		&fileHandle,
		FILE_GENERIC_WRITE,
		&oa,
		&osb,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_WRITE,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	return 0;

}