//this module implements Intel VMX specific functions
#include "mypervisor.h"
BOOLEAN VmxProbe(VOID) {
	INT cpu_info[4];
	ULONGLONG featureControl;
	//cpuid opcode gives information about the processor
	__cpuid(cpu_info, 1);
	//check the hypervisor-present bit
	if ((cpu_info[2] & 0x20) == FALSE) {
		return FALSE;
	}

	//Check if the Feature Control MSR is locked, if it isnt, this means
	//that bios/uefi firmware screwed up and we rather not mess with it
	featureControl = __readmsr(IA32_FEATURE_CONTROL_MSR);
	if (!featureControl & IA32_FEATURE_CONTROL_MSR_LOCK) {
		return FALSE;
	}
	//the Feature-Control MSR is locked-in (valid), is VMX enabled in 
	//normal operation mode?
	if (!(featureControl & IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_OUTSIDE_SMX)) {
		return FALSE;
	}

	//Both hardware and firmware are allowing us to enter VMX mode
	return TRUE;
}
//function to enable VMX root mode and activate the VMCS
BOOLEAN VmxEnterRootModeOnVp(_In_ PSHV_VP_DATA VpData) {
	PKSPECIAL_REGISTERS Registers = &VpData->HostState.SpecialRegisters;

	//check if VMCS can fit on a single page
	if (((VpData->MsrData[0].QuadPart & VMX_BASIC_VMCS_SIZE_MASK) >> 32) > PAGE_SIZE) {
		return FALSE;
	}
	//Ensure that VMCS is supported in writeback memory
	if (((VpData->MsrData[0].QuadPart & VMX_BASIC_MEMORY_TYPE_MASK) >> 50) != MTRR_TYPE_WB) {
		return FALSE;
	}
	//Ensure that true MSRs can be used for capabilities
	if (((VpData->MsrData[0].QuadPart) & VMX_BASIC_DEFAULT1_ZERO) == 0) {
		return FALSE;
	}
	//capture the revision id for vmxon and vmcs region
	VpData->VmxOn.RevisionId = VpData->MsrData[0].LowPart;
	VpData->Vmcs.RevisionId = VpData->MsrData[0].LowPart;

	//Update Cr0 with the must-be-zero and must-be-one requirements
	Registers->Cr0 &= VpData->MsrData[7].LowPart;
	Registers->Cr0 |= VpData->MsrData[6].LowPart;

	//Same for Cr4
	Registers->Cr4 &= VpData->MsrData[9].LowPart;
	Registers->Cr4 |= VpData->MsrData[8].LowPart;

	//update Host Cr0 and Cr4 
	__writecr0(Registers->Cr0);
	__writecr4(Registers->Cr4);

	//Enable VMX Root Mode
	if (__vmx_on(&VpData->VmxOnPhysicalAddress)) {
		return FALSE;
	}
	//Clear VMCS, setting it to inactive
	if (__vmx_vmclear(&VpData->VmcsPhysicalAddress)) {
		return FALSE;
	}

	//Load te VMCS, setting its state to active
	if (__vmx_vmptrld(&VpData->VmcsPhysicalAddress)) {
		return FALSE;
	}

	//VMX Root mode is enabled, with an active VMCS
	return TRUE;
}
//Function to initialize the VMCS
VOID VmxSetupVmcsForVp(_In_ PSHV_VP_DATA VpData) {

	PKPROCESSOR_STATE state = &VpData->HostState;
	VMX_GDTENTRY64 vmxGdtEntry;

	//set link pointer to the reuired value for 4KB VMCS
	__vmx_vmwrite(VMCS_LINK_POINTER, MAXULONG64);
	//load the MSR bitmap. unlike other bitmaps, this one is necessary.
	__vmx_vmwrite(MSR_BITMAP, VpData->MsrBitmapPhysicalAddress);

	//Enable support for RDTSCP and XSAVES/XRESOTREs
	//Win 10 makes use of both of these instructions if the CPU supports it.
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, UtilAdjustMsr(VpData->MsrData[11], SECONDARY_EXEC_ENABLE_RDTSCP | SECONDARY_EXEC_XSAVES));

	//Enable no pin-based options ourselves, may be some required by the processor
	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, UtilAdjustMsr(VpData->MsrData[13], 0));

	//in order to support RDTSCP and XSAVE/RESTORES, we have to request
	//secondary controls. also want to activate the MSR bitmap in order
	//to keep them from being caught
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, UtilAdjustMsr(VpData->MsrData[14], CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS));

	//If any interrupts were pending upon entering the hypervisor, acknowledge
	//them when we're done. Make sure to enter x64 mode at all times
	__vmx_vmwrite(VM_EXIT_CONTROLS, UtilAdjustMsr(VpData->MsrData[15], VM_EXIT_ACK_INTR_ON_EXIT | VM_EXIT_IA32E_MODE));

	//as we exit back into the guest, make sure to exist in x64 mode
	__vmx_vmwrite(VM_ENTRY_CONTROLS, UtilAdjustMsr(VpData->MsrData[16], VM_ENTRY_IA32E_MODE));

	//LOAD CS Segment
	UtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegCs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_CS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_CS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_CS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_CS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_CS_SELECTOR, state->ContextFrame.SegCs & ~RPL_MASK);
	//LOAD SS Segment
	UtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegSs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_SS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_SS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_SS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_SS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_SS_SELECTOR, state->ContextFrame.SegSs & ~RPL_MASK);
	//LOAD DS Segment
	UtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegDs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_DS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_DS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_DS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_DS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_DS_SELECTOR, state->ContextFrame.SegDs & ~RPL_MASK);
	//LOAD ES Segment
	UtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegEs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_ES_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_ES_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_ES_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_ES_SELECTOR, state->ContextFrame.SegEs & ~RPL_MASK);
	//LOAD FS Segment
	UtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegFs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_FS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_FS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_FS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_FS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_FS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_FS_SELECTOR, state->ContextFrame.SegFs & ~RPL_MASK);
	//LOAD GS Segment
	UtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegGs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_GS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_GS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_GS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_GS_BASE, state->SpecialRegisters.MsrGsBase);
	__vmx_vmwrite(HOST_GS_BASE, state->SpecialRegisters.MsrGsBase);
	__vmx_vmwrite(HOST_GS_SELECTOR, state->ContextFrame.SegGs & ~RPL_MASK);
	//LOAD Task Register
	UtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->SpecialRegisters.Tr, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_TR_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_TR_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_TR_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_TR_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_TR_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_TR_SELECTOR, state->SpecialRegisters.Tr & ~RPL_MASK);
	//Load Local Descriptor Table
	UtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->SpecialRegisters.Ldtr, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_LDTR_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_LDTR_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_LDTR_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_LDTR_BASE, vmxGdtEntry.Base);
	//LOAD GDT
	__vmx_vmwrite(GUEST_GDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Gdtr.Base);
	__vmx_vmwrite(GUEST_GDTR_LIMIT, state->SpecialRegisters.Gdtr.Limit);
	__vmx_vmwrite(HOST_GDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Gdtr.Base);
	//LOAD IDT
	__vmx_vmwrite(GUEST_IDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Idtr.Base);
	__vmx_vmwrite(GUEST_IDTR_LIMIT, state->SpecialRegisters.Idtr.Limit);
	__vmx_vmwrite(HOST_IDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Idtr.Base);
	//LOAD CR0
	__vmx_vmwrite(CR0_READ_SHADOW, state->SpecialRegisters.Cr0);
	__vmx_vmwrite(HOST_CR0, state->SpecialRegisters.Cr0);
	__vmx_vmwrite(GUEST_CR0, state->SpecialRegisters.Cr0);
	//LOAD CR3
	__vmx_vmwrite(HOST_CR3, VpData->SystemDirectoryTableBase);
	__vmx_vmwrite(GUEST_CR3, state->SpecialRegisters.Cr3);
	//LOAD CR4
	__vmx_vmwrite(HOST_CR4, state->SpecialRegisters.Cr4);
	__vmx_vmwrite(GUEST_CR4, state->SpecialRegisters.Cr4);
	__vmx_vmwrite(CR4_READ_SHADOW, state->SpecialRegisters.Cr4);
	//Load Debug MSR and Register (DR7)
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, state->SpecialRegisters.DebugControl);
	__vmx_vmwrite(GUEST_DR7, state->SpecialRegisters.KernelDr7);
	//load guest stack, instruction pointer, and rflags
	__vmx_vmwrite(GUEST_RSP, state->ContextFrame.Rsp);
	__vmx_vmwrite(GUEST_RIP, state->ContextFrame.Rip);
	__vmx_vmwrite(GUEST_RFLAGS, state->ContextFrame.EFlags);
	//load hypervisor entry point and stack
	//use standard size kernel stack 24k and bias for the context
	//structure that the hypervisor entrypoint will push on the stack,
	//avoiding the need for RSP modifying instructions in the entrypoint.
	C_ASSERT((KERNEL_STACK_SIZE - sizeof(CONTEXT)) % 16 == 0);
	__vmx_vmwrite(HOST_RSP, (ULONG_PTR)VpData->ShvStackLimit + KERNEL_STACK_SIZE - sizeof(CONTEXT));
	__vmx_vmwrite(HOST_RIP, (ULONG_PTR)VmxEntry);
}

VOID VmxLaunchOnVp(_In_ PSHV_VP_DATA VpData) {
	
	ULONG i;
	//initialze all VMX related msrs by reading their value
	for (i = 0; i < RTL_NUMBER_OF(VpData->MsrData); i++) {
		VpData->MsrData[i].QuadPart = __readmsr(MSR_IA32_VMX_BASIC + i);
	}
	//attempt to enter root mode on the processor
	if (VmxEnterRootModeOnVp(VpData)) {
		//Initialize the VMCS for both guest and host state.
		VmxSetupVmcsForVp(VpData);
		//record that VMX is now enabled
		VpData->VmxEnabled = 1;
		//Launch the VMCS, based on the data that was loaded into the various 
		//VMCS fields this will cause the processor to 
		//jump to the return address of RtlCaptureContext in
		//ShvVpInitialize
		__vmx_vmlaunch();
		//execution should not get here, only get here if we failed to vmlaunch
		__vmx_off();
	}

}