#pragma once
#pragma warning(disable:4201)
#pragma warning(disable:4214)
#include <ntifs.h>
#include <intrin.h>
#include "ntint.h"
#include "vmx.h"


typedef struct _VMX_GDTENTRY64
{
	ULONG_PTR Base;
	ULONG Limit;
	union
	{
		struct
		{
			UCHAR Flags1;
			UCHAR Flags2;
			UCHAR Flags3;
			UCHAR Flags4;
		} Bytes;
		struct
		{
			USHORT SegmentType : 4;
			USHORT DescriptorType : 1;
			USHORT Dpl : 2;
			USHORT Present : 1;

			USHORT Reserved : 4;
			USHORT System : 1;
			USHORT LongMode : 1;
			USHORT DefaultBig : 1;
			USHORT Granularity : 1;

			USHORT Unusable : 1;
			USHORT Reserved2 : 15;
		} Bits;
		ULONG AccessRights;
	};
	USHORT Selector;
} VMX_GDTENTRY64, *PVMX_GDTENTRY64;

typedef struct DECLSPEC_ALIGN(PAGE_SIZE) _VMX_VMCS
{
	ULONG RevisionId;
	ULONG AbortIndicator;
	UCHAR Data[PAGE_SIZE - 8];
} VMX_VMCS, *PVMX_VMCS;

typedef struct _SHV_VP_DATA
{
	KPROCESSOR_STATE HostState;
	ULONG VpIndex;
	volatile ULONG VmxEnabled;
	ULONG64 SystemDirectoryTableBase;
	LARGE_INTEGER MsrData[17];
	ULONGLONG VmxOnPhysicalAddress;
	ULONGLONG VmcsPhysicalAddress;
	ULONGLONG MsrBitmapPhysicalAddress;

	DECLSPEC_ALIGN(PAGE_SIZE) UCHAR ShvStackLimit[KERNEL_STACK_SIZE];
	VMX_VMCS VmxOn;
	VMX_VMCS Vmcs;
} SHV_VP_DATA, *PSHV_VP_DATA;

C_ASSERT(sizeof(SHV_VP_DATA) == (KERNEL_STACK_SIZE + 3 * PAGE_SIZE));

typedef struct _SHV_GLOBAL_DATA
{
	UCHAR MsrBitmap[PAGE_SIZE];
	SHV_VP_DATA VpData[ANYSIZE_ARRAY];
} SHV_GLOBAL_DATA, *PSHV_GLOBAL_DATA;

typedef struct _SHV_VP_STATE
{
	PCONTEXT VpRegs;
	ULONG_PTR GuestRip;
	ULONG_PTR GuestRsp;
	ULONG_PTR GuestEFlags;
	USHORT ExitReason;
	KIRQL GuestIrql;
	BOOLEAN ExitVm;
} SHV_VP_STATE, *PSHV_VP_STATE;

extern PSHV_GLOBAL_DATA HvGlobalData;

//Util Headers
ULONG UtilAdjustMsr(_In_ LARGE_INTEGER ControlValue, _In_ ULONG DesiredValue);
VOID UtilConvertGdtEntry(_In_ PVOID GdtBase, _In_ USHORT Selector, _Out_ PVMX_GDTENTRY64 VmxGdtEntry);

//Vmx Headers
BOOLEAN VmxProbe(VOID);
VOID VmxLaunchOnVp(_In_ PSHV_VP_DATA VpData);

//x64.asm Headers
VOID VmxEntry(VOID);
VOID __lgdt(_In_ PVOID Gdtr);
VOID HvCleanup(_In_ USHORT Data, _In_ USHORT Teb);

//VirtualProcessor Headers
PSHV_GLOBAL_DATA VpAllocateGlobalData(VOID);
KDEFERRED_ROUTINE VpCallbackDpc;

//Hypervisor Headers
VOID HvEntryHandler(_In_ PCONTEXT Context);