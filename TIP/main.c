#pragma once
#include "tipheader.h"
#pragma comment(lib, "ntdll")
#define MEASURE TRUE

int main()
{
	HMODULE instCallbackdll = LoadLibraryW(PICEDLL); //Import PICE implementation

#define COUNTER 1000
#ifdef MEASURE
	LARGE_INTEGER StartingTime, EndingTime, ElapsedMicroseconds, Frequency;
	ULONG_PTR totalCPUUserTime, totalCPUKernelTime, startUserTime, stopUserTime, startKernelTime, stopKernelTime;
	PROCESS_MEMORY_COUNTERS memCounter;
	DWORD cbmemCounter = sizeof(PROCESS_MEMORY_COUNTERS);

	wprintf(L"Beginning test with %d files\n", COUNTER);
	
	recordProcessTime(&startUserTime, &startKernelTime); //Begin tracking CPU execution time spent in UM and KM
	

	QueryPerformanceFrequency(&Frequency);
	QueryPerformanceCounter(&StartingTime); //Beginning tracking real (wall) execution time

	//
	// stressTest() does the following tasks utilizing WinAPI:
	//
	// 1. Writes COUNTER number of files to disk
	// 2. Writes "Hello World!" to each file
	// 3. Reads contents of each file into a buffer
	// 4. Deletes each file
	//
	stressTest(COUNTER);

	/*
	##############################################################################################################################
	//Finish tracking execution time
	##############################################################################################################################
	*/
	QueryPerformanceCounter(&EndingTime);	//Finish tracking real (wall) execution time
	recordProcessTime(&stopUserTime, &stopKernelTime);	//Finish tracking CPU execution time spent in UM and KM
	GetProcessMemoryInfo(NtCurrentProcess(), &memCounter, cbmemCounter); //Record memory usage up to this point

	//FreeLibrary(instCallbackdll); //Optional since the program will exit


	//
	// Transform time objects into human readable output
	//
	//https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps

	ElapsedMicroseconds.QuadPart = EndingTime.QuadPart - StartingTime.QuadPart;
	ElapsedMicroseconds.QuadPart *= 1000000; //Convert ticks (pico?)to Microseconds
	ElapsedMicroseconds.QuadPart /= Frequency.QuadPart; //Divide by the ticks-per-clock set by the CPU
	//ElapsedMicroseconds.QuadPart /= 1000000; //convert Microseconds to Seconds (1000000)

	totalCPUUserTime = stopUserTime - startUserTime; //Get time elasped since last function call
	totalCPUUserTime /= 10; //Convert 100-nanosecond intervals to microseconds (1000000 for seconds)

	totalCPUKernelTime = stopKernelTime - startKernelTime; //Get time elasped since last function call
	totalCPUKernelTime /= 10; //Convert 100-nanosecond intervals to microseconds (1000000 for seconds)

	//printf("[WALL] Total Time in MicroSeconds:   %I64d\n", ElapsedMicroseconds.QuadPart);
	//printf("[USER] Total time in MicroSeconds:   %I64d\n", totalCPUUserTime);
	//printf("[KERNEL] Total time in Microseconds: %I64d\n", totalCPUKernelTime);
	//printf("[VIRTUAL] Total memory usage:  %d bytes\n", memCounter.PeakPagefileUsage);
	//printf("[PHYSICAL] Total memory usage: %d bytes\n", memCounter.PeakWorkingSetSize);
	wprintf(L"%I64d,%I64d,%I64d,%I64d,%I64d\n", ElapsedMicroseconds.QuadPart, totalCPUUserTime, totalCPUKernelTime, memCounter.PeakPagefileUsage, memCounter.PeakWorkingSetSize);
#endif
	//	printf("Last Error: %d", GetLastError());
	return 0;
}