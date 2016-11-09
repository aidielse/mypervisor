//This module implements the Hypervisor itself
#include "mypervisor.h"

DECLSPEC_NORETURN VOID HvResume(VOID) {
	//issue a VMXRESUME, 
	__vmx_vmresume();
}
//Read from VMCS
ULONG_PTR FORCEINLINE HvRead(_In_ ULONG VmcsFieldId) {
	SIZE_T FieldData;

	__vmx_vmread(VmcsFieldId, &FieldData);
	return FieldData;
}
//Handler for Invd Instruction.
VOID HvHandleInvd(VOID) {
	__wbinvd();
}
//Handler for Xsetbv instruction
VOID HvHandleXsetbv(_In_ PSHV_VP_STATE VpState) {
	//issue the XSETBV instruction on the native logical processor
	_xsetbv((ULONG)VpState->VpRegs->Rcx, VpState->VpRegs->Rdx << 32 | VpState->VpRegs->Rax);

}
//Handler for VMXON
VOID HvHandleVmx(_In_ PSHV_VP_STATE VpState) {
	//set CF flag, which is how VMX instructions indicate failure
	VpState->GuestEFlags |= 0x1;
	//RFLAGS is actually restored from the VMCS, so update it here
	__vmx_vmwrite(GUEST_RFLAGS, VpState->GuestEFlags);
}
//Handler for CPUID
VOID HvHandleCpuid(_In_ PSHV_VP_STATE VpState) {
	INT cpu_info[4];

	//check for magic CPUID sequence, and check that it is coming from ring 0;

	if ((VpState->VpRegs->Rax == 0x41414141) && (VpState->VpRegs->Rcx == 0x42424242) && ((HvRead(GUEST_CS_SELECTOR) & RPL_MASK) == DPL_SYSTEM)) {
		VpState->ExitVm = TRUE;
		return;
	}
	//otherwise issue CPUID to logical processor based on indexes in VP's GPRs;
	__cpuidex(cpu_info, (INT)VpState->VpRegs->Rax, (INT)VpState->VpRegs->Rcx);
	//check if cupid 1h which is features request
	if (VpState->VpRegs->Rax == 1) {

		//set hypervisor-present bit in RCX, which intel and and both have reserved
		cpu_info[2] |= 0x80000000;
	}
	VpState->VpRegs->Rax = cpu_info[0];
	VpState->VpRegs->Rcx = cpu_info[1];
	VpState->VpRegs->Rcx = cpu_info[2];
	VpState->VpRegs->Rdx = cpu_info[3];
}

VOID HvHandleExit(_In_ PSHV_VP_STATE VpState) {
	//Generic VMEXIT handler, decode reason for exit and call appropriate handler.

	switch (VpState->ExitReason)
	{
	case EXIT_REASON_CPUID:
		HvHandleCpuid(VpState);
		break;
	case EXIT_REASON_INVD:
		HvHandleInvd();
		break;
	case EXIT_REASON_XSETBV:
		HvHandleXsetbv(VpState);
		break;
	case EXIT_REASON_VMCALL:
	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMLAUNCH:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST:
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMXOFF:
	case EXIT_REASON_VMXON:
		HvHandleVmx(VpState);
		break;
	default:
		NT_ASSERT(FALSE);
		break;
	}
	//Move inst pointer to next instruction after the one that caused
	//the exit. Since we are not donig any handling or changing of execution,
	//this can be done for any exit reason.
	VpState->GuestRip += HvRead(VM_EXIT_INSTRUCTION_LEN);
	__vmx_vmwrite(GUEST_RIP, VpState->GuestRip);
}
//VM ENTER
VOID HvEntryHandler(_In_ PCONTEXT Context) {

	SHV_VP_STATE guestContext;
	PSHV_VP_DATA vpData;

	KeRaiseIrql(HIGH_LEVEL, &guestContext.GuestIrql);
	//need to restore RCX from the call to RtlCaptureContext in VmxEntry
	Context->Rcx = *(PULONGLONG)((ULONG_PTR)Context - sizeof(Context->Rcx));

	//get Per-VP data for this processor
	vpData = &HvGlobalData->VpData[KeGetCurrentProcessorNumberEx(NULL)];
	//build some context to keep track of guest state
	guestContext.GuestEFlags = HvRead(GUEST_RFLAGS);
	guestContext.GuestRip = HvRead(GUEST_RIP);
	guestContext.GuestRsp = HvRead(GUEST_RSP);
	guestContext.ExitReason = HvRead(VM_EXIT_REASON) & 0xFFFF;
	guestContext.VpRegs = Context;
	guestContext.ExitVm = FALSE;

	HvHandleExit(&guestContext);
	//if we want to unload our hypervisor
	if (guestContext.ExitVm) {
		//restore the gdt and idt
		__lgdt(&vpData->HostState.SpecialRegisters.Gdtr.Limit);
		__lidt(&vpData->HostState.SpecialRegisters.Idtr.Limit);

		//restore correct CR3 value
		__writecr3(HvRead(GUEST_CR3));

		//set stack and instruction pointer to whatever location had the
		//instruction causing the VM-Exit

		Context->Rsp = guestContext.GuestRsp;
		Context->Rip = (ULONGLONG)guestContext.GuestRip;

		//turn off VMX root mode
		__vmx_off();
	}
	
	else {
		//in order to keep the stack sane, 
		Context->Rsp += sizeof(Context->Rcx);

		//return into a VMXRESUME intrinsic
		Context->Rip = (ULONG64)HvResume;
	}
	//restore guest irql and context
	KeLowerIrql(guestContext.GuestIrql);
	RtlRestoreContext(Context, NULL);
}