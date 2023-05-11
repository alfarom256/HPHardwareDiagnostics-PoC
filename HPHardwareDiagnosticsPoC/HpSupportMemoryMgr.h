#pragma once
#include <Windows.h>
#include <stdio.h>

#define IOCTL_READ 0x8000603C
#define IOCTL_WRITE 0x8000A038


#define GLE( x ) { printf("%s failed - %d\n", x, GetLastError()); }

static void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		}
		else {
			ascii[i % 16] = '.';
		}
		if ((i + 1) % 8 == 0 || i + 1 == size) {
			printf(" ");
			if ((i + 1) % 16 == 0) {
				printf("|  %s \n", ascii);
			}
			else if (i + 1 == size) {
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i + 1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

typedef struct _EDTI_READ {
	UINT64 szRead; // 1, 2, 4
	UINT64 reserved0;
	UINT64 src;
	UINT32 data;
	UINT32 reserved1;
} EDTI_READ, * PEDTI_READ;

typedef struct _EDTI_WRITE {
	UINT64 szWrite; // 1, 2, 4
	UINT64 reserved0;
	UINT64 where;
	UINT64 what;
} EDTI_WRITE, * PEDTI_WRITE;

union EDTI_DATA {
	EDTI_READ read;
	EDTI_WRITE write;
};

class HpSupportMemoryMgr
{
public:
	HANDLE hDevice = INVALID_HANDLE_VALUE;

	BOOL ReadVirtData(UINT64 src, SIZE_T szRead, PVOID data);
	BOOL WriteVirtData(UINT64 dest, SIZE_T szWrite, PVOID data);
	
	HpSupportMemoryMgr();
	BOOL init();
};

