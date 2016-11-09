#pragma once
#include <default.h>
#pragma pack(1)
//This library contains code for handling the MBR of a physical Disk
//Written by Aaron Sedlacek
//Last Updated: 07/13/2016

//This struct describes a partition descriptor within the MBR's Partition Table
typedef struct _PARTITION {
	BYTE Status;				//Boot Status, 0x80 - active partition, 0x00 - partition non bootable	
	BYTE StartingHead;			//Starting head of the partition
	BYTE StartingSector;		//Starting sector of the partition
	BYTE StartingCylinder;		//Least significant bits of the starting cylinder
	BYTE PartitionType;			//System Identifier ( BOOT ID)
	BYTE EndingHead;			//Ending Head of the Partition
	BYTE EndingSector;			//Ending Sector of the Partition
	BYTE EndingCylinder;		//Ending Cylinder of the partition
	DWORD StartSectorOffset;	//Offset of the partition from the start of the partition table (in sectors)
	DWORD TotalSectors;			//titak number of sectors in the partition
}PARTITION, *PPARTITION;
//This struct describes the mbr
//I think the sizes of the DiskParameters, MBRBootCode, and DiskSignature fields are wrong, but the PartitionTable is right and that's what counts!
typedef struct _MBR {
	BYTE Jmp[0x3]; //0x00-0x02
	BYTE DiskParameters[0x3A]; //0x03-0x3D
	BYTE MBRBootCode[0x17B]; //0x3E - 0x1B8
	BYTE DiskSignature[0x6]; //0x1B8- 0x1BD
	PARTITION PartitionTable[4];
}MBR, *PMBR;
#pragma pack()
//Prints a partition from the MBR Partition table
NTSTATUS PrintPartition(PARTITION Partition) {

	DbgPrint("[PrintPartition]: Status: 0x%x\n", Partition.Status);
	DbgPrint("[PrintPartition]: Starting Head: 0x%x\n", Partition.StartingHead);
	DbgPrint("[PrintPartition]: Starting Sector: 0x%x\n", Partition.StartingSector);
	DbgPrint("[PrintPartition]: Starting Cylinder: 0x%x\n", Partition.StartingCylinder);
	DbgPrint("[PrintPartition]: Partition Type: 0x%x\n", Partition.PartitionType);
	DbgPrint("[PrintPartition]: Ending Head: 0x%x\n", Partition.EndingHead);
	DbgPrint("[PrintPartition]: Ending Sector: 0x%x\n", Partition.EndingSector);
	DbgPrint("[PrintPartition]: Ending Cylinder: 0x%x\n", Partition.EndingCylinder);
	DbgPrint("[PrintPartition]: Start Sector Offset: 0x%x\n", Partition.StartSectorOffset);
	DbgPrint("[PrintPartition]: Total Sectors: 0x%x\n", Partition.TotalSectors);

	return STATUS_SUCCESS;
}
//Prints out the MBR, again, think some variables in the struct might be incorrect? Jmp and Partition table are definitely correct though
NTSTATUS PrintMbr(MBR Mbr) {
	DbgPrint("Jmp: %1x%1x%1x\n", Mbr.Jmp[0], Mbr.Jmp[1], Mbr.Jmp[2]);
	
	int i = 0;
	DbgPrint("Disk Parameters:\n");
	for (i; i < 0x3a; i++) {
		DbgPrint("\t0x%1x\n", Mbr.DiskParameters[i]);
	}
	DbgPrint("\n");

	i = 0;
	DbgPrint("MBR Boot Code: \n");
	for (i; i < 0x17B; i++) {
		DbgPrint("\t0x%1x\n", Mbr.MBRBootCode[i]);
	}
	DbgPrint("\n");
	i = 0;

	DbgPrint("Disk Signature: 0x");
	for (i; i < 0x6; i++) {
		DbgPrint("%1x", Mbr.DiskSignature[i]);
	}
	DbgPrint("\n");

	i = 0;
	for (i; i < 0x4; i++) {
		DbgPrint("Partition %d: \n\n",i);
		PrintPartition(Mbr.PartitionTable[i]);
		DbgPrint("\n");
	}
	return STATUS_SUCCESS;
}

//Reads the MBR into pMBR
NTSTATUS ReadMbr(HANDLE DriveHandle, PMBR pMbr) {
	NTSTATUS status = STATUS_SUCCESS;
	status = ReadFile(DriveHandle, (PVOID)pMbr, 512, 0);
	return status;
}
//Write pMbr to MBR
NTSTATUS WriteMbr(HANDLE DriveHandle, PMBR pMbr) {
	NTSTATUS status = STATUS_SUCCESS;
	status = WriteFile(DriveHandle, (PVOID)pMbr, 512, 0);
	return status;
}