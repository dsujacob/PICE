#include "tipheader.h"
//https://stackoverflow.com/questions/19378805/measure-cpu-time-on-windows-using-getprocesstimes
void recordProcessTime(PULONG_PTR userTime, PULONG_PTR kernelTime)
{
	FILETIME CreationTime, ExitTime, KernelTime, UserTime;
	ULARGE_INTEGER userTimeStruct, kernelTimeStruct;
	if (GetProcessTimes(NtCurrentProcess(), &CreationTime, &ExitTime, &KernelTime, &UserTime))
	{
		//Microsoft reccomends changing the structure before peforming arithmetic operations
		userTimeStruct.LowPart = UserTime.dwLowDateTime;
		userTimeStruct.HighPart = UserTime.dwHighDateTime;

		kernelTimeStruct.LowPart = KernelTime.dwLowDateTime;
		kernelTimeStruct.HighPart = KernelTime.dwHighDateTime;

		*userTime = userTimeStruct.QuadPart;
		*kernelTime = kernelTimeStruct.QuadPart;
	}	

}
