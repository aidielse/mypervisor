//utility functions are implemented here
#include "mypervisor.h"
//VMX feature msrs encode the must-be-zero bits in the high part, and 
//must-be-one bits in the low part. 

ULONG UtilAdjustMsr(_In_ LARGE_INTEGER ControlValue, _In_ ULONG DesiredValue) {
	//Adjust any requested feature based on must-be-one/must-be-zero bit requirements.	
	DesiredValue &= ControlValue.HighPart;
	DesiredValue |= ControlValue.LowPart;

	return DesiredValue;
}

VOID UtilConvertGdtEntry(_In_ PVOID GdtBase, _In_ USHORT Selector, _Out_ PVMX_GDTENTRY64 VmxGdtEntry) {

	PKGDTENTRY64 gdtEntry;

	//read GDT entry at the given selector, masking out the RPL bits.
	//x64 Windows does not use an LDT for these selectors in kernel
	//TI Bit should never be set
	
	NT_ASSERT((Selector & SELECTOR_TABLE_INDEX) == 0);
	gdtEntry = (PKGDTENTRY64)((ULONG_PTR)GdtBase + (Selector & ~RPL_MASK));

	//Write the selector directly
	VmxGdtEntry->Selector = Selector;
	//use LSL intrinsic to read the segment limit
	VmxGdtEntry->Limit = __segmentlimit(Selector);

	//Build full 64 bit effective address, keeping in mind that only the System bit
	// is unset, should this be done
	VmxGdtEntry->Base = ((gdtEntry->Bytes.BaseHigh << 24) | (gdtEntry->Bytes.BaseMiddle << 16) | (gdtEntry->BaseLow)) & MAXULONG;
	VmxGdtEntry->Base |= ((gdtEntry->Bits.Type & 0x10) == 0) ? ((ULONG_PTR)gdtEntry->BaseUpper << 32) : 0;
	//load access rights
	VmxGdtEntry->AccessRights = 0;
	VmxGdtEntry->Bytes.Flags1 = gdtEntry->Bytes.Flags1;
	VmxGdtEntry->Bytes.Flags2 = gdtEntry->Bytes.Flags2;
	//handle VMX-specific bits
	VmxGdtEntry->Bits.Reserved = 0;
	VmxGdtEntry->Bits.Unusable = !gdtEntry->Bits.Present;
}