//This module implements Virtual Processor Management
#include "mypervisor.h"

PSHV_GLOBAL_DATA VpAllocateGlobalData(VOID) {
	PHYSICAL_ADDRESS lowest, highest;
	PSHV_GLOBAL_DATA data;
	ULONG cpuCount, size;

	//allocation can go anywhere in the address range
	lowest.QuadPart = 0;
	highest.QuadPart = lowest.QuadPart - 1;
	//query the number of logical processors
	cpuCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	//each processor recieves a slice of per-virtual processor data
	size = FIELD_OFFSET(SHV_GLOBAL_DATA, VpData) + cpuCount * sizeof(SHV_VP_DATA);
	//allocate contiguous chunk of RAM to back teh allocation
	//make sure RW only, instead of RWX, by using API call introduced in Win 8
	data = (PSHV_GLOBAL_DATA)MmAllocateContiguousNodeMemory(size, lowest, highest, lowest, PAGE_READWRITE, MM_ANY_NODE_OK);

	if (data != NULL)
	{
		// Zero out the entire data region
		__stosq((PULONGLONG)data, 0, size / sizeof(ULONGLONG));
	}
	// Return what is hopefully a valid pointer, otherwise NULL.
	return data;
}

VOID VpInitialize(_In_ PSHV_VP_DATA Data, _In_ ULONGLONG SystemDirectoryTableBase) {
 
	//Store hibernation state of the processor, contains all special registers
	//and MSRS which are what the VMCS will need as part of its setup
	//avoids using assembly and manually reading this data
	KeSaveStateForHibernate(&Data->HostState);

	//Capture entire register state, once we launch the vm it will begin
	//execution at the defined guest instruction pointer, which is captured
	//as part of this call. AKA the vm will begin execution right here.
	RtlCaptureContext(&Data->HostState.ContextFrame);

	//If the vm has launched, we need to restore the general purpose registers
	if (HvGlobalData->VpData[KeGetCurrentProcessorNumberEx(NULL)].VmxEnabled == 1) {
		//Indicate that the vm has fully launched.
		
		HvGlobalData->VpData[KeGetCurrentProcessorNumberEx(NULL)].VmxEnabled = 2;
		//After we restore the general purpose reigsters and stack state
		//execution will continue at the previous call to RtlCaptureContext
		RtlRestoreContext(&HvGlobalData->VpData[KeGetCurrentProcessorNumberEx(NULL)].HostState.ContextFrame, NULL);
	}
	//IF we  have not yet attempted to launch the VM
	else if (Data->VmxEnabled == 0) {

		//Capture the Page table for system process,
		//this is done so that all virtual processors can share correct kernel
		//address space
		Data->SystemDirectoryTableBase = SystemDirectoryTableBase;
		
		VmxLaunchOnVp(Data);
	}
}

VOID VpUninitialize(_In_ PSHV_VP_DATA VpData) {
	INT dummy[4];
	UNREFERENCED_PARAMETER(VpData);

	//send magic shutdown instruction sequence

	__cpuidex(dummy, 0x41414141, 0x42424242);

	//processor will return here after hypervisor issues a VMXOFF instruction
	//and restores the cpu context to this location
	//RtlRestoreContext uses a iretq, which causes the processor to 
	//remove the RPL bits off of the segments.
	//these bits need to be restored.

	HvCleanup(KGDT64_R3_DATA | RPL_MASK, KGDT64_R3_CMTEB | RPL_MASK);
}

VOID VpCallbackDpc(_In_ PRKDPC Dpc, _In_opt_ PVOID Context, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2) {

	UNREFERENCED_PARAMETER(Dpc);


	//Get the per-vp data for this logical processor
	PSHV_VP_DATA vpData = &HvGlobalData->VpData[KeGetCurrentProcessorNumberEx(NULL)];
	
	//check if loading or unloading
	if (ARGUMENT_PRESENT(Context)) {
		VpInitialize(vpData,(ULONGLONG) Context);
	}
	else {
		//Not Implemented
		VpUninitialize(vpData);
	}
	//wait for all dpcs to synchronize to this point
	KeSignalCallDpcSynchronize(SystemArgument2);
	//mark DPC's as complete
	KeSignalCallDpcDone(SystemArgument1);
}