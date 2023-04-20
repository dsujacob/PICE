.code
	NtCreateFile proc
			mov r10, rcx
			mov eax, 55h ;55h is the SysCall # for NtCreateFile
			syscall		 ; Execute the system call
			ret
	NtCreateFile endp
end