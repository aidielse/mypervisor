#pragma once
#include <default.h>
#include <mbr.h>
//This library contains code for dealing with the NTFS VBR (Volume Boot Record)

#define SZ_SECTOR			512	//Size of a sector on disk

#pragma pack(1)
//Struct to define the fields of the traditional NTFS Volume Boot Record
typedef struct _BOOT_SECTOR {
	BYTE Jmp[3];					//Jump Instruction
	BYTE OemID[8];					//OEM ID
	//-------BPB-------
	WORD BytesPerSector;			//Bytes per Sector
	BYTE SectorsPerCluster;			//Sectors per cluster
	WORD ReservedSectors;			//Number of reserved sectors, usually equals 0
	BYTE Filler_1[20];				//Not used by NTFS or us
	//-------EBPB-------
	BYTE Filler_2[4];				//Not used by NTFS or us
	QWORD TotalDiskSectors;			//Total number of sectors
	QWORD MftLCN;					//Mft Logical Cluster Number
	QWORD MftMirrLCN;				// MFT Mirror logical cluster number
	BYTE ClustersPerMFTFileRecord;	//Number of clusters per file record segment
	BYTE Filler_3[3];			
	BYTE ClustersPerMFTIndexRecord;	//Number of clusters per index block
	BYTE Filler_4[3];
	QWORD VolumeSN;					//Serial Number
	BYTE Filler_5[4];
	BYTE Code[426];					//Volume Boot Sector Code
	WORD EndOfSector;				//0x55 0xAA
}BOOT_SECTOR, *PBOOT_SECTOR;
//this struct describes a physical sector on disk
typedef struct _SECTOR {
	BYTE Buffer[SZ_SECTOR];
} SECTOR, *PSECTOR;
//this struct describes a physical cluster on disk
typedef struct _CLUSTER {
	SECTOR Sector[8];
} CLUSTER, *PCLUSTER;
#pragma pack()

//this function takes a physical disk as an argument and returns the Volume Boot Record of the first partition
//this function also populates a MBR struct
HANDLE ReadBootSectorFromPhysicalDisk(UNICODE_STRING PhysicalDiskName, PMBR pMbr, PBOOT_SECTOR pBootSector, BYTE PartitionNo) {
	
	HANDLE Handle = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	//get a handle to the disk device
	Handle = GetFileHandle(PhysicalDiskName);
	if (Handle == NULL) {
		DbgPrint("GetDeviceHandle Failed!\n");
		return NULL;
	}
	//read the MBR into the Mbr struct
	status = ReadMbr(Handle, pMbr);
	if (!NT_SUCCESS(status)) {
		DbgPrint("ReadMbr Failed! in GetBootSector!\n");
	}
	//read the bootloader
	status = ReadFile(Handle, (PVOID)pBootSector, sizeof(BOOT_SECTOR), (pMbr->PartitionTable[PartitionNo].StartSectorOffset * SZ_SECTOR));
	if (!NT_SUCCESS(status)) {
		DbgPrint("ReadFile Failed! in GetBootSector!\n");
	}
	return Handle;
}
//reads the boot sector from a logical drive. 
HANDLE ReadBootSectorFromLogicalDrive(UNICODE_STRING DriveName, PBOOT_SECTOR pBootSector) {
	HANDLE Handle = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	Handle = GetFileHandle(DriveName);
	if (Handle == NULL) {
		DbgPrint("GetDeviceHandle Failed!\n");
		return NULL;
	}

	status = ReadFile(Handle, (PVOID)pBootSector, sizeof(BOOT_SECTOR), 0);
	if (!NT_SUCCESS(status)) {
		DbgPrint("ReadFile Failed! in GetBootSector!\n");
	}

	return Handle;
}
//this function calculates the correct number of clusters, I think we only use this in the PrintBootSector function below
//the NumClusterPerMFTFileRecord and NumClusterPerMFTIndexRecord fields are stored weirdly sometimes, this function fixes them.
BYTE CorrectNumClusters(BYTE ClustersPerRecord, WORD BytesPerSector, BYTE SectorsPerCluster) {
	signed char nClusters;
	DWORD nSectors;

	nClusters = (signed char)ClustersPerRecord;
	if (nClusters < 0)
	{
		DWORD nBytes = 1;
		int i;

		// nBytes = 2^abs(nClusters)
		nClusters = (signed char)abs(nClusters);
		for (i = 0; i < nClusters; i++) { nBytes = nBytes * 2; }

		nSectors = (nBytes / BytesPerSector);
		nClusters = (signed char)(nSectors / SectorsPerCluster);

	}
	return((BYTE)nClusters);
}
//This function prints information about the boot sector
NTSTATUS PrintBootSector(PBOOT_SECTOR pBootSector) {

	BYTE NumClustersPerMFTFileRecord = CorrectNumClusters(pBootSector->ClustersPerMFTFileRecord, pBootSector->BytesPerSector, pBootSector->SectorsPerCluster);
	BYTE NumClustersPerMFTIndexRecord = CorrectNumClusters(pBootSector->ClustersPerMFTIndexRecord, pBootSector->BytesPerSector, pBootSector->SectorsPerCluster);

	DbgPrint("[PrintBootSector]: Bytes Per Sector: %d\n", pBootSector->BytesPerSector);
	DbgPrint("[PrintBootSector]: Sectors Per Cluster: %d\n", pBootSector->SectorsPerCluster);
	DbgPrint("[PrintBootSector]: Total Disk Sectors: %I64x\n", pBootSector->TotalDiskSectors);
	DbgPrint("[PrintBootSector]: Master File Table LCN: %I64x\n", pBootSector->MftLCN);
	DbgPrint("[PrintBootSector]: Master File Table Mirror LCN: %I64x\n", pBootSector->MftMirrLCN);
	DbgPrint("[PrintBootSector]: Number of Clusters Per MFT File Record: %d\n", NumClustersPerMFTFileRecord);
	DbgPrint("[PrintBootSector]: Number of Clusters Per MFT Index Record: %d\n", NumClustersPerMFTIndexRecord);
	DbgPrint("[PrintBootSector]: Volume Serial Number: %I64x\n", pBootSector->VolumeSN);

	return STATUS_SUCCESS;
}