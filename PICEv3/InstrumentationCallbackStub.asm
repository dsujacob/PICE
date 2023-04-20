include ksamd64.inc
;Inspiration:
;https://github.com/xenoscr/manual-syscall-detect/blob/main/manual-syscall-detect/manual-syscall-detect/InstrumentationCallbackProxy.asm
extern InstrumentationCallback:proc
EXTERNDEF __imp_RtlCaptureContext:QWORD

.code

InstrumentationCallbackStub proc
	;Recursion check
	push	rax					;Save old RAX value
	mov		rax, 1			
	cmp		gs:[2ech], rax		;Check to see if the cbDisableOffset has been set to True
	je		resume				;Skip PIC since we are already in the middle of instrumenting a call

	pop rax

	;int 3					;Manual breakpoint for inspection in WinDBG

	;Save the stack pointer that we intercepted
	mov     gs:[2e0h], rsp            ; Win10 TEB InstrumentationCallbackPreviousSp
	;Save the return address that we intercepted
	mov     gs:[2d8h], r10            ; Win10 TEB InstrumentationCallbackPreviousPc

	mov     r10, rcx                  ; Save original RCX
	sub     rsp, 4d0h                 ; Alloc stack space for CONTEXT structure
	and     rsp, -10h                 ; RSP must be 16 byte aligned before calls
	mov     rcx, rsp
	;Setup RCX for RtlCaptureContext call
	call    __imp_RtlCaptureContext   ; Save the current register state. RtlCaptureContext does not require shadow space
	;int 3
	sub     rsp, 20h                  ; Shadow space
	call	InstrumentationCallback   ; Call main instrumentation routine


resume:
	pop rax
	jmp r10
InstrumentationCallbackStub endp

end