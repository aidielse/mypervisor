include ksamd64.inc

    extern HvEntryHandler:proc
    extern RtlCaptureContext:proc

    NESTED_ENTRY VmxEntry, _TEXT$00

    push_reg rcx                ; save RCX, as we will need to orverride it
    END_PROLOGUE                ; done messing with the stack

    lea     rcx, [rsp+8h]       ; store the context in the stack, bias for
                                ; the return address and the push we just did.
    call    RtlCaptureContext   ; save the current register state.
                                ; note that this is a specially written function
                                ; which has the following key characteristics:
                                ;   1) it does not taint the value of RCX
                                ;   2) it does not spill any registers, nor
                                ;      expect home space to be allocated for it

    jmp     HvEntryHandler		; jump to the C code handler. we assume that it
                                ; compiled with optimizations and does not use
                                ; home space, which is true of release builds.

    NESTED_END VmxEntry, _TEXT$00

    LEAF_ENTRY HvCleanup, _TEXT$00

    mov     ds, cx              ; set DS to parameter 1
    mov     es, cx              ; set ES to parameter 1
    mov     fs, dx              ; set FS to parameter 2
    ret                         ; return

    LEAF_END HvCleanup, _TEXT$00

    LEAF_ENTRY __lgdt, _TEXT$00

    lgdt    fword ptr [rcx]     ; load the GDTR with the value in parameter 1
    ret                         ; return

    LEAF_END __lgdt, _TEXT$00

    end
