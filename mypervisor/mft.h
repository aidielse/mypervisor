#pragma once
#include <default.h>
//This is a library for working with the master file table
//By: Aaron Sedlacek
//Last Updated: 07/13/2016

#define SZ_MFT_HEADER		48		// MFT Header Size
#define SZ_FILENAME			25			
#define SZ_ATTRIBUTE_HDR	24		//MFT Attribute Header Size
#define SZ_MFT_RECORD		1024	//MFT Record Size

//MFT Record Header Types (Didnt really use in the PoC, but still defined anyway)				
#define MFT_FILE    0x454c4946	// Mft file or directory
#define MFT_INDX    0x58444e49	// Index buffer
#define MFT_HOLE    0x454c4f48	// ? (NTFS 3.0+?)
#define MFT_RSTR    0x52545352	// Restart page
#define MFT_RCRD    0x44524352	// Log record page
#define MFT_CHKD    0x444b4843	// Modified by chkdsk
#define MFT_BAAD    0x44414142	// Failed multi-sector transfer was detected
#define MFT_empty   0xffffffff	// Record is empty, not initialized
#define MFT_ZERO    0x00000000  // zeroes!

//MFT Attribute Types (Didnt really use in the PoC, but still defined anyway)
#define ATTR_STANDARD_INFORMATION   0x00000010
#define ATTR_LIST					0x00000020
#define ATTR_FILE_NAME              0x00000030
#define ATTR_VOLUME_VERSION			0x00000040
#define ATTR_OBJECT_ID				0x00000040
#define ATTR_SECURITY_DESCRIPTOR	0x00000050
#define ATTR_VOLUME_NAME			0x00000060
#define ATTR_VOLUME_INFORMATION		0x00000070
#define ATTR_DATA					0x00000080
#define ATTR_INDEX_ROOT				0x00000090
#define ATTR_INDEX_ALLOCATION		0x000000a0
#define ATTR_BITMAP					0x000000b0
#define ATTR_SYMBOLIC_LINK			0x000000c0
#define ATTR_REPARSE_POINT			0x000000c0
#define ATTR_EA_INFORMATION			0x000000d0
#define ATTR_EA						0x000000e0
#define ATTR_PROPERTY_SET			0x000000f0
#define ATTR_LOGGED_UTILITY_STREAM	0x00000100

#pragma pack(1)
//MFT Record Header
typedef struct _MFT_HEADER {
	DWORD Magic;						//FILE Signature
	WORD UpdateSequenceOffset;			//Update Sequence Number
	WORD UpdateSequenceSize;			//Update Sequence Number and array
	QWORD LogFileSequenceNumber;		//$LogFile Sequence Number
	WORD SequenceNumber;				//Sequence Number
	WORD NumHardLinks;					//Number of Hard Links
	WORD FirstAttr;						//Offset of the First Attribute
	WORD Flags;							//Flags, 0x00 = not used, 0x01 = in use and describes file, 0x02 = in use and describes directory, 
	DWORD BytesUsed;					//Real size of the file record
	DWORD BytesAllocated;				//Allocated size of the file record
	QWORD BaseRecord;					//File reference to the base file record, or zero if this file record is the base one
	WORD NextAttributeId;				//Next Attribute Identifier
	WORD Reserved;						//For aligment
	DWORD RecordNumber;					//Number of this MFT Record
}MFT_HEADER, *PMFT_HEADER;
#pragma pack()
//struct for a resident MFT attribute
#pragma pack(1)
typedef struct RES_ATTR_HEADER {
	DWORD Type;							//Attribute Type
	DWORD Length;						//Attribute Full Length
	BYTE NonResident;					//Resident = 0, Nonresident = 1
	BYTE NameLen;						//Length of the attribute name
	WORD NameOffset;					//Offset of the Attribute Name
	WORD Flags;							//Generic Flags
	WORD AttrIdentifier;				//Attribute Identifier
	DWORD ValueLength;					//Length of the Attribute Body, without the header
	WORD ValueOffset;					//Offset of attribute body
	BYTE IndexFlag;						//Index Flag
	BYTE Unused;						//For alignment
}RES_ATTR_HEADER, *PRES_ATTR_HEADER;
#pragma pack()
//struct for a nonresident MFT attribute
#pragma pack(1)
typedef struct NONRES_ATTR_HEADER {
	DWORD Type;							//Attribute Type
	DWORD Length;						//Attribute Full Length
	BYTE NonResident;					//Resident Flag
	BYTE NameLen;						//Length of the Attribute Name
	WORD NameOffset;					//Offset of the attribute name
	WORD Flags;							//Generic Flags
	WORD AttrIdentifier;				//Attribute Identifier
	QWORD StartingVCN;					//Starting Volume Cluster Number
	QWORD LastVCN;						//Last Volume Cluster Number 
	WORD DataRunsOffset;				//Offset of Data Runs Struct
	WORD CompressionUnitSize;			//Compression Unit Size
	DWORD Unused;						//For Alignment
}NONRES_ATTR_HEADER, *PNONRES_ATTR_HEADER;
#pragma pack()
//MFT Record Struct
#pragma pack(1)
typedef struct _MFT_RECORD {
	MFT_HEADER MFTHeader;				//MFT Record Header
	BYTE Data[976];						//MFT data, composed of multiple attributes
}MFT_RECORD, *PMFT_RECORD;
#pragma pack()
//Data Run Struct
#pragma pack(1)
typedef struct _DATA_RUN {
	QWORD Length;						//Data Run length (in Clusters)
	QWORD StartCluster;					//Start Cluster of the Data Run
}DATA_RUN, *PDATA_RUN;
#pragma pack()

//this function Reads a Single MFT Record into the buffer pointed to by pRecord
//It uses the mbr and the bootsector structs to determine the offset of the MFT on the physical disk.
NTSTATUS ReadMftRecordFromPhysicalDisk(HANDLE Handle, PMBR pmbr, BYTE PartitionNo, PBOOT_SECTOR pBootSector, PMFT_RECORD pRecord, ULONGLONG RecordNo) {

	NTSTATUS status = STATUS_SUCCESS;
	ULONGLONG MftByteOffset;
	
	ULONGLONG PhysicalOffset = RecordNo * SZ_MFT_RECORD;
	//offset into logical disk
	MftByteOffset = pBootSector->MftLCN;
	MftByteOffset = MftByteOffset * pBootSector->SectorsPerCluster;
	MftByteOffset = MftByteOffset * pBootSector->BytesPerSector;
	MftByteOffset = MftByteOffset + PhysicalOffset;
	//add start of Logical Disk offset
	MftByteOffset = MftByteOffset + pmbr->PartitionTable[PartitionNo].StartSectorOffset * SZ_SECTOR;
	//Read record from physical disk
	status = ReadFile(Handle, (PVOID)pRecord, SZ_MFT_RECORD, MftByteOffset);

	if (!NT_SUCCESS(status)) {
		DbgPrint("ReadFile Failed! 0x%x\n", status);
		pRecord = NULL;
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}
//This function writes a single record to the MFT using Raw I/O
//This function was not used by my PoC, it was replaced by RawWrite from default.h
NTSTATUS WriteMFTRecord(HANDLE Handle, PMBR pmbr, BYTE PartitionNo, PBOOT_SECTOR pBootSector, PMFT_RECORD pRecord, ULONGLONG RecordNo) {
	
	//will be used in the future	
	NTSTATUS status = STATUS_SUCCESS;
	IO_STATUS_BLOCK IoStatusBlock;
	PFILE_OBJECT pFileObject;
	KEVENT Event;
	PIRP pIrp;
	
	//Get the device object belonging to \\Device\\HardDisk0\\DR0
	status = ObReferenceObjectByHandle(Handle, GENERIC_READ | GENERIC_WRITE, *IoFileObjectType, KernelMode, &pFileObject, NULL);

	if (!NT_SUCCESS(status)) {
		DbgPrint("ObReferenceObjectByHandle in WriteMFTRecord Failed! 0x%x\n", status);
		return STATUS_UNSUCCESSFUL;
	}

	//get a pointer to the device object from the file object
	PDEVICE_OBJECT pDeviceObject = pFileObject->DeviceObject;

	//init event for IoCallDriver
	KeInitializeEvent(&Event, NotificationEvent, FALSE);
	
	LARGE_INTEGER Offset;
	ULONGLONG PhysicalOffset = RecordNo * SZ_MFT_RECORD;
	//offset into logical disk
	Offset.QuadPart = pBootSector->MftLCN;
	Offset.QuadPart = Offset.QuadPart * pBootSector->SectorsPerCluster;
	Offset.QuadPart = Offset.QuadPart * pBootSector->BytesPerSector;
	Offset.QuadPart = Offset.QuadPart + PhysicalOffset;
	//add start of Logical Disk offset
	Offset.QuadPart = Offset.QuadPart + pmbr->PartitionTable[PartitionNo].StartSectorOffset * SZ_SECTOR;

	DbgPrint("Writting to offset %llx\n", Offset.QuadPart);
	//build IRP 
	pIrp = IoBuildSynchronousFsdRequest(IRP_MJ_WRITE, pDeviceObject, (PVOID)pRecord, (ULONG)SZ_MFT_RECORD, &Offset, &Event, &IoStatusBlock);

	if (pIrp == NULL) {
		DbgPrint("IoBuildSynchronousFsdRequest Failed!\n");
		return STATUS_UNSUCCESSFUL;
	}
	DbgPrint("%x\n", IoStatusBlock.Status);

	PIO_STACK_LOCATION pIrpSp = IoGetNextIrpStackLocation(pIrp);
	//Enable raw io write
	pIrpSp->Flags |= SL_FORCE_DIRECT_WRITE;
	//send IRP
	status = IoCallDriver(pDeviceObject, pIrp);

	DbgPrint("Status: 0x%x\n", status);
	//wait for our irp to complete
	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
	}

	else if (!NT_SUCCESS(status)) {
		DbgPrint("IoCallDriver Messed Up? 0x%x\n", status);
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}
//Debug print out the mft header
NTSTATUS PrintMftHeader(PMFT_RECORD pMftRecord) {
	DbgPrint("MFT HEADER:\n");
	DbgPrint("\tMagic: 0x%x\n", pMftRecord->MFTHeader.Magic);
	DbgPrint("\tUpdate Sequence Offset: 0x%x\n", pMftRecord->MFTHeader.UpdateSequenceOffset);
	DbgPrint("\tUpdate Sequence Size: 0x%x\n", pMftRecord->MFTHeader.UpdateSequenceSize);
	DbgPrint("\tLogFile Sequence Number: 0x%x\n", pMftRecord->MFTHeader.LogFileSequenceNumber);
	DbgPrint("\tSequence Number: 0x%x\n", pMftRecord->MFTHeader.SequenceNumber);
	DbgPrint("\tNumber of Hard Links: 0x%x\n", pMftRecord->MFTHeader.NumHardLinks);
	DbgPrint("\tFirst Attribute: 0x%x\n", pMftRecord->MFTHeader.FirstAttr);
	DbgPrint("\tFlags: 0x%x\n", pMftRecord->MFTHeader.Flags);
	DbgPrint("\tBytes Used: 0x%x\n", pMftRecord->MFTHeader.BytesUsed);
	DbgPrint("\tBytes Allocated: 0x%x\n", pMftRecord->MFTHeader.BytesAllocated);
	DbgPrint("\tBase Record: 0x%x\n", pMftRecord->MFTHeader.BaseRecord);
	DbgPrint("\tNext Attribute Id: 0x%x\n", pMftRecord->MFTHeader.NextAttributeId); 
	DbgPrint("\tRecord Number: 0x%x\n", pMftRecord->MFTHeader.RecordNumber);

	return STATUS_SUCCESS;
}
//Debug Print out a Resident MFT Attribute
NTSTATUS PrintResAttribute(PRES_ATTR_HEADER pResAttrHeader) {
	DbgPrint("MFT Record Resident Attribute:\n");
	DbgPrint("\tType: 0x%x\n", pResAttrHeader->Type);
	DbgPrint("\tLength: 0x%x\n", pResAttrHeader->Length);
	DbgPrint("\tNon Resident: 0x%x\n", pResAttrHeader->NonResident);
	DbgPrint("\tName Length: 0x%x\n", pResAttrHeader->NameLen);
	DbgPrint("\tName Offset: 0x%x\n", pResAttrHeader->NameOffset);
	DbgPrint("\tFlags: 0x%x\n", pResAttrHeader->Flags);
	DbgPrint("\tAttribute Identifier: 0x%x\n", pResAttrHeader->AttrIdentifier);
	DbgPrint("\tValue Length: 0x%x\n", pResAttrHeader->ValueLength);
	DbgPrint("\tValue Offset: 0x%x\n", pResAttrHeader->ValueOffset);
	DbgPrint("\tIndex Flag: 0x%x\n", pResAttrHeader->IndexFlag);

	return STATUS_SUCCESS;
}
//Debug Print out a Non-Resident MFT Attribute
NTSTATUS PrintNonResAttribute(PNONRES_ATTR_HEADER pNonResAttrHeader) {
	DbgPrint("MFT Record Non-Resident Attribute:\n");
	DbgPrint("\tType: 0x%x\n", pNonResAttrHeader->Type);
	DbgPrint("\tLength: 0x%x\n", pNonResAttrHeader->Length);
	DbgPrint("\tNon Resident: 0x%x\n", pNonResAttrHeader->NonResident);
	DbgPrint("\tName Length: 0x%x\n", pNonResAttrHeader->NameLen);
	DbgPrint("\tName Offset: 0x%x\n", pNonResAttrHeader->NameOffset);
	DbgPrint("\tFlags: 0x%x\n", pNonResAttrHeader->Flags);
	DbgPrint("\tAttribute Identifier: 0x%x\n", pNonResAttrHeader->AttrIdentifier);
	DbgPrint("\tStarting VCN: 0x%x\n", pNonResAttrHeader->StartingVCN);
	DbgPrint("\tLast VCN: 0x%x\n", pNonResAttrHeader->LastVCN);
	DbgPrint("\tData Runs Offset: 0x%x\n", pNonResAttrHeader->DataRunsOffset);
	DbgPrint("\tCompression Unit Size: 0x%x\n", pNonResAttrHeader->CompressionUnitSize);

	return STATUS_SUCCESS;
}

//This function parses and Debug prints an MFT record
NTSTATUS ParseMftRecord(PMFT_RECORD pMftRecord) {

	PrintMftHeader(pMftRecord);
	//get offset of first attribute
	DWORD AttrOffset = pMftRecord->MFTHeader.FirstAttr;
	AttrOffset = AttrOffset - SZ_MFT_HEADER;
	
	//this variable keeps an eye out for 0xFFFFFFFF, which marks the end of the record
	DWORD * EndMarker = (DWORD *)((pMftRecord->Data) + AttrOffset);
	//while not at the end of the record
	while (*EndMarker != 0xffffffff) {

		//if Resident Attribute, print
		if (pMftRecord->Data[AttrOffset + 8] == 0x00) {
			RES_ATTR_HEADER foo;
			//copy the attribute into foo, then print it out
			memcpy(&foo, &(pMftRecord->Data[AttrOffset]), sizeof(RES_ATTR_HEADER));
			PrintResAttribute(&foo);

			//This for loop prints the data that is not in the header but still part of the attribute
			int i = 0;
			DbgPrint("\tData: \n");
			for (i; i < foo.Length - sizeof(RES_ATTR_HEADER); i++) {
				DbgPrint("\t\t0x%x: 0x%x\n", sizeof(RES_ATTR_HEADER) +i, pMftRecord->Data[AttrOffset + sizeof(RES_ATTR_HEADER) + i]);
			}
			//move to the next record
			AttrOffset = AttrOffset + foo.Length;
		}
		//if non resident attribute
		else {
			NONRES_ATTR_HEADER foo;
			//copy the attribute into foo, then print it out
			memcpy(&foo, &(pMftRecord->Data[AttrOffset]), sizeof(NONRES_ATTR_HEADER));
			PrintNonResAttribute(&foo);
			//This for loop prints the data that is not in the header but still part of the attribute
			int i = 0;
			DbgPrint("\tData: \n");
			for (i; i < foo.Length - sizeof(NONRES_ATTR_HEADER); i++) {
				DbgPrint("\t\t0x%x: 0x%x\n", sizeof(NONRES_ATTR_HEADER) + i, pMftRecord->Data[AttrOffset + sizeof(NONRES_ATTR_HEADER) + i]);
			}
			//move to the next record
			AttrOffset = AttrOffset + foo.Length;
		}
		DbgPrint("\n");
		//move the end marker forward
		EndMarker = (DWORD *)((pMftRecord->Data) + AttrOffset);
	}
	
	return STATUS_SUCCESS;
}
//Gets the first data run struct encountered, allocates a new pool that contains said struct and returns the size of said pool.
//this function follows the same logic as the previous function but populates the DataRunStruct variable
SIZE_T GetFirstDataRun(PMFT_RECORD pMftRecord, BYTE ** DataRunStruct) {
	//get offset of first attribute
	SIZE_T Size = 0;
	DWORD AttrOffset = pMftRecord->MFTHeader.FirstAttr;
	AttrOffset = AttrOffset - SZ_MFT_HEADER;

	//this variable keeps an eye out for the end of the record
	DWORD * EndMarker = (DWORD *)((pMftRecord->Data) + AttrOffset);
	//while not at the end of the record
	while (*EndMarker != 0xffffffff) {

		//if Resident Attribute:
		if (pMftRecord->Data[AttrOffset + 8] == 0x00) {
			DbgPrint("Resident Attribute Found\n");
			//copy the resident attribute to foo
			RES_ATTR_HEADER foo;
			memcpy(&foo, &(pMftRecord->Data[AttrOffset]), sizeof(RES_ATTR_HEADER));
			//move to the next record
			AttrOffset = AttrOffset + foo.Length;
		}
		//if non resident attribute
		else {
			NONRES_ATTR_HEADER foo;
			//copy nonres attribute into foo
			DbgPrint("NonResident Attribute Found\n");
			memcpy(&foo, &(pMftRecord->Data[AttrOffset]), sizeof(NONRES_ATTR_HEADER));
			//data run usually comes at the end of the file? this may be slightly buggy
			Size = foo.Length - foo.DataRunsOffset;
			DbgPrint("Size: 0x%x\n", Size);
			//allocate a pool to hold the data run struct and copy the struct into it
			*DataRunStruct = (BYTE *) ExAllocatePoolWithTag(NonPagedPool, Size, '1gaT');
			memcpy(*DataRunStruct, &(pMftRecord->Data[AttrOffset + foo.DataRunsOffset]), Size);
			break;
		}
		//move the end marker pointer forward
		EndMarker = (DWORD *)((pMftRecord->Data) + AttrOffset);
	}

	return Size;
}
//Extracts the cluster location of a data run from the data run struct, returns a populated data_run struct
DATA_RUN ParseDataRunStruct(BYTE * DataRunStruct) {

	SIZE_T track = 0;
	//be wary of sparse attributes which can have a size descriptor of zero
	//get the size descriptor nibbles from the first byte
	BYTE LengthFieldSize = DataRunStruct[track] & 0x0F;
	BYTE InitialClusterFieldSize = (DataRunStruct[track] & 0xF0) >> 4;

	DbgPrint("Length Field Size: 0x%x\n Initial Cluster Field Size: 0x%x\n", LengthFieldSize, InitialClusterFieldSize);
	//allocate pools to hold the length field and the first cluster field
	BYTE * LengthField = ExAllocatePool(NonPagedPool, LengthFieldSize);
	BYTE * StartCluster = ExAllocatePool(NonPagedPool, InitialClusterFieldSize);
	//extract the length fields from the struct
	memcpy(LengthField, &(DataRunStruct[track + 1]), LengthFieldSize);
	memcpy(StartCluster, &(DataRunStruct[track + LengthFieldSize + 1]), InitialClusterFieldSize);

	DATA_RUN DataRun;
	DataRun.Length = 0;
	DataRun.StartCluster = 0;
	//convert the endianness of the fields and populate datarun struct.
	int i = 1;
	for (i; i <= LengthFieldSize; i++) {
		DataRun.Length = DataRun.Length + ((LengthField[LengthFieldSize - i]) << 8 * (LengthFieldSize - i));
	}

	i = 1;
	for (i; i <= InitialClusterFieldSize; i++) {
		DataRun.StartCluster = DataRun.StartCluster + ((StartCluster[InitialClusterFieldSize - i]) << 8 * (InitialClusterFieldSize - i));
	}

	ExFreePool(LengthField);
	ExFreePool(StartCluster);
	//track = track + LengthFieldSize + InitialClusterFieldSize + 1;
	
	return DataRun;
}