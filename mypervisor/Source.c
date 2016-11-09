#include "mypervisor.h"
#include "default.h"
//mypervisor, hypervisor by Aidielse
//started on: 07/28/2016
//heavily influenced by Simplevisor by Alex Ionescu
PSHV_GLOBAL_DATA HvGlobalData;
//Hypervisor/Driver unload routine
NTSTATUS HypervisorUnload(PDRIVER_OBJECT pDriverObject) {
	UNREFERENCED_PARAMETER(pDriverObject);
	//exit VMX root mode on all logical processors
	KeGenericCallDpc(VpCallbackDpc, NULL);
	if (HvGlobalData != NULL)
	{
		MmFreeContiguousMemory(HvGlobalData);
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[mypervisor]: Hypervisor Unloaded\n");

	return STATUS_SUCCESS;
}
//Entry Point
NTSTATUS DriverEntry( _In_ PDRIVER_OBJECT pDriverObject, _In_ PUNICODE_STRING pRegPath) {
	UNREFERENCED_PARAMETER(pRegPath);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[mypervisor]: Entering DriverEntry\n");
	pDriverObject->DriverUnload = HypervisorUnload;
	//If hypervisor is present, exit early
	if (HviIsAnyHypervisorPresent()) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID,0,"[mypervisor]: Hypervisor already loaded\n");
		return STATUS_HV_OBJECT_IN_USE;
	}
	//Check if hardware and firmware will allow us to enter VMX root mode
	if (!VmxProbe()) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID,0,"[mypervisor]: Hardware/firmware do not support VMX root mode\n");
		return STATUS_HV_FEATURE_UNAVAILABLE;
	}
	//Allocate global shared data which all virtual processors will share
	HvGlobalData = VpAllocateGlobalData();

	if (!HvGlobalData) {
		return STATUS_HV_INSUFFICIENT_BUFFER;
	}

	//Attempt to enter VMX root mode on all logical processors.
	//broadcast a DPC interrupt which will exec the callback routine
	//on all Logical processors. 

	//Send the callback routine the address of the PML4 (first page table) of the system process

	NT_ASSERT(PsGetCurrentProcess() == PsInitialSystemProcess);

	KeGenericCallDpc(VpCallbackDpc, (PVOID)__readcr3());

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[mypervisor]: Exiting DriverEntry\n");

	return STATUS_SUCCESS;
}