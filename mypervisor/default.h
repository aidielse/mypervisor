#pragma once
#include <ntifs.h>
//This header file contains generic functions that I found myself using repeatedly throughout multiple drivers
//By: Aaron Sedlacek
//Last Updated: 07/13/2016

typedef unsigned long long QWORD;
typedef unsigned long DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;

//Function to be used as generic unload routine
NTSTATUS DefaultUnload(PDRIVER_OBJECT pDriverObject) {
	UNREFERENCED_PARAMETER(pDriverObject);

	return STATUS_SUCCESS;
}
//Function to be used as generic IRP Dispatch Handler
NTSTATUS DefaultDispatch(PDEVICE_OBJECT pDeviceObject, PIRP pIRP) {
	UNREFERENCED_PARAMETER(pDeviceObject);

	pIRP->IoStatus.Status = STATUS_SUCCESS;
	pIRP->IoStatus.Information = 0;

	IoCompleteRequest(pIRP, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}
//given a pointer and a length, dumps a region of memory a byte at a time
NTSTATUS DbgDump(PCHAR Address, int size) {
	int i = 0;

	for (i; i < size; i++) {
		DbgPrint("[DbgDump]: 0x%llx - 0x%1x\n", (Address + i), *(Address + i) & 0x000000ff);
	}

	return STATUS_SUCCESS;
}
//Function to get a handle to a File Object
HANDLE GetFileHandle(UNICODE_STRING DeviceName) {
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE DriveHandle;
	OBJECT_ATTRIBUTES ObjAttr;
	IO_STATUS_BLOCK IoStatusBlock;

	//Initialize Object Attributes, required for ZwOpenFile
	InitializeObjectAttributes(&ObjAttr, &DeviceName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwOpenFile(&DriveHandle, GENERIC_READ | GENERIC_WRITE, &ObjAttr, &IoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);

	if (!NT_SUCCESS(status)) {
		DbgPrint("ZwOpenFile Failed in GetDeviceHandle: 0x%x\n", status);
		return NULL;
	}

	return DriveHandle;
}

//Reads data from a File Handle
NTSTATUS ReadFile(HANDLE FileHandle, PVOID Buffer, int BufferSize, ULONGLONG Offset) {
	NTSTATUS status = STATUS_SUCCESS;
	IO_STATUS_BLOCK IoStatusBlock;

	LARGE_INTEGER Off;
	Off.QuadPart = Offset;

	status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, Buffer, BufferSize, &Off, NULL);

	if (!NT_SUCCESS(status)) {
		DbgPrint("ZwReadFile Failed 0x%x\n", status);
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}
//Writes Data to a File Handle
NTSTATUS WriteFile(HANDLE FileHandle, PVOID Buffer, ULONG BufferSize, ULONGLONG Offset) {
	NTSTATUS status = STATUS_SUCCESS;
	IO_STATUS_BLOCK IoStatusBlock;

	LARGE_INTEGER Off;
	Off.QuadPart = Offset;

	status = ZwWriteFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, Buffer, BufferSize, &Off, NULL);

	if (!NT_SUCCESS(status)) {
		DbgPrint("ZwWriteFile Failed 0x%x\n", status);
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

//Takes in a File handle to the physical disk and writes raw data to the disk.
NTSTATUS RawWrite(HANDLE Handle, BYTE * Buffer, DWORD BuffLen, ULONGLONG PhysicalOffset) {

	NTSTATUS status = STATUS_SUCCESS;
	IO_STATUS_BLOCK IoStatusBlock;
	PFILE_OBJECT pFileObject;
	KEVENT Event;
	PIRP pIrp;
	//Populate the FILE_OBJECT Struct
	status = ObReferenceObjectByHandle(Handle, GENERIC_READ | GENERIC_WRITE, *IoFileObjectType, KernelMode, &pFileObject, NULL);

	if (!NT_SUCCESS(status)) {
		DbgPrint("ObReferenceObjectByHandle in RawWrite Failed! 0x%x\n", status);
	}
	//get pointer to hard disk device object from the FILE_OBJECT
	PDEVICE_OBJECT pDeviceObject = pFileObject->DeviceObject;
	//Initialize event to track completion of our irp
	KeInitializeEvent(&Event, NotificationEvent, FALSE);

	LARGE_INTEGER Offset;
	Offset.QuadPart = PhysicalOffset;

	//DbgPrint("Writing 0x%x bytes to offset %llx\n", BuffLen ,Offset.QuadPart);
	//build our raw_Write IRP
	pIrp = IoBuildSynchronousFsdRequest(IRP_MJ_WRITE, pDeviceObject, (PVOID)Buffer, (ULONG)BuffLen, &Offset, &Event, &IoStatusBlock);

	if (pIrp == NULL) {
		DbgPrint("IoBuildSynchronousFsdRequest Failed!\n");
		return STATUS_UNSUCCESSFUL;
	}
	//Get a pointer to the stack location that belongs to the device we are sending our IRP to
	PIO_STACK_LOCATION pIrpSp = IoGetNextIrpStackLocation(pIrp);
	//Enable raw io write
	pIrpSp->Flags |= SL_FORCE_DIRECT_WRITE;
	//send IRP to the device
	status = IoCallDriver(pDeviceObject, pIrp);
	//wait for irp to complete
	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
	}

	else if (!NT_SUCCESS(status)) {
		DbgPrint("IoCallDriver Messed Up? 0x%x\n", status);
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}
