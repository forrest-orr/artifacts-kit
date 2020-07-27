/*
____________________________________________________________________________________________________
| 			   __  .__  _____               __     __   .__  __                                    |
| _____ ________/  |_|__|/ ____\____    _____/  |_  |  | _|__|/  |_                                |
| \__  \\_  __ \   __\  \   __\\__  \ _/ ___\   __\ |  |/ /  \   __\                               |
|  / __ \|  | \/|  | |  ||  |   / __ \\  \___|  |   |    <|  ||  |                                 |
| (____  /__|   |__| |__||__|  (____  /\___  >__|   |__|_ \__||__|                                 |
|      \/                           \/     \/            \/                                        |
|__________________________________________________________________________________________________|
| Pseudo-malicious memory artifact kit                                                             |
|--------------------------------------------------------------------------------------------------|
| https://www.forrest-orr.net/post/masking-malicious-memory-artifacts-part-ii-insights-from-moneta |
|--------------------------------------------------------------------------------------------------|
| Author: Forrest Orr - 2020                                                                       |
|--------------------------------------------------------------------------------------------------|
| Contact: forrest.orr@protonmail.com                                                              |
|--------------------------------------------------------------------------------------------------|
| Licensed under GNU GPLv3                                                                         |
|__________________________________________________________________________________________________|
| ## Features                                                                                      |
|                                                                                                  |
| ~ Generate dynamic image, mapped and private memory                                              |
| ~ Bootstrap PE files                                                                             |
| ~ Phantom and classic DLL hollowing                                                              |
| ~ Moating, header wiping, and header mirroring                                                   |
|__________________________________________________________________________________________________|

*/

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>

IMAGE_SECTION_HEADER* GetContainerSectHdr(IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHeader, uint64_t qwRVA) {
	for (uint32_t dwX = 0; dwX < pNtHdrs->FileHeader.NumberOfSections; dwX++) {
		IMAGE_SECTION_HEADER* pCurrentSectHdr = pInitialSectHeader;
		uint32_t dwCurrentSectSize;

		pCurrentSectHdr += dwX;

		if (pCurrentSectHdr->Misc.VirtualSize > pCurrentSectHdr->SizeOfRawData) {
			dwCurrentSectSize = pCurrentSectHdr->Misc.VirtualSize;
		}
		else {
			dwCurrentSectSize = pCurrentSectHdr->SizeOfRawData;
		}

		if ((qwRVA >= pCurrentSectHdr->VirtualAddress) && (qwRVA <= (pCurrentSectHdr->VirtualAddress + dwCurrentSectSize))) {
			return pCurrentSectHdr;
		}
	}

	return nullptr;
}

void* GetPAFromRVA(uint8_t* pPeBuf, IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHdrs, uint64_t qwRVA) {
	IMAGE_SECTION_HEADER* pContainSectHdr;

	if ((pContainSectHdr = GetContainerSectHdr(pNtHdrs, pInitialSectHdrs, qwRVA)) != nullptr) {
		uint32_t dwOffset = (qwRVA - pContainSectHdr->VirtualAddress);

		if (dwOffset < pContainSectHdr->SizeOfRawData) { // Sections can be partially or fully virtual. Avoid creating physical pointers that reference regions outside of the raw data in sections with a greater virtual size than physical.
			return (uint8_t*)(pPeBuf + pContainSectHdr->PointerToRawData + dwOffset);
		}
	}

	return nullptr;
}

bool CheckRelocRange(uint8_t* pRelocBuf, uint32_t dwRelocBufSize, uint32_t dwStartRVA, uint32_t dwEndRVA) {
	IMAGE_BASE_RELOCATION* pCurrentRelocBlock;
	uint32_t dwRelocBufOffset, dwX;
	bool bWithinRange = false;

	for (pCurrentRelocBlock = (IMAGE_BASE_RELOCATION*)pRelocBuf, dwX = 0, dwRelocBufOffset = 0; pCurrentRelocBlock->SizeOfBlock; dwX++) {
		uint32_t dwNumBlocks = ((pCurrentRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t));
		uint16_t* pwCurrentRelocEntry = (uint16_t*)((uint8_t*)pCurrentRelocBlock + sizeof(IMAGE_BASE_RELOCATION));

		for (uint32_t dwY = 0; dwY < dwNumBlocks; dwY++, pwCurrentRelocEntry++) {
#ifdef _WIN64
#define RELOC_FLAG_ARCH_AGNOSTIC IMAGE_REL_BASED_DIR64
#else
#define RELOC_FLAG_ARCH_AGNOSTIC IMAGE_REL_BASED_HIGHLOW
#endif
			if (((*pwCurrentRelocEntry >> 12) & RELOC_FLAG_ARCH_AGNOSTIC) == RELOC_FLAG_ARCH_AGNOSTIC) {
				uint32_t dwRelocEntryRefLocRva = (pCurrentRelocBlock->VirtualAddress + (*pwCurrentRelocEntry & 0x0FFF));

				if (dwRelocEntryRefLocRva >= dwStartRVA && dwRelocEntryRefLocRva < dwEndRVA) {
					bWithinRange = true;
				}
			}
		}

		dwRelocBufOffset += pCurrentRelocBlock->SizeOfBlock;
		pCurrentRelocBlock = (IMAGE_BASE_RELOCATION*)((uint8_t*)pCurrentRelocBlock + pCurrentRelocBlock->SizeOfBlock);
	}

	return bWithinRange;
}

int32_t GetCodeSection(IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pSectHdrs, uint32_t dwMinSize) {
	for (int32_t nX = 0; nX < pNtHdrs->FileHeader.NumberOfSections; nX++) {
		if (((pSectHdrs + nX)->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
			if (dwMinSize) {
				uint32_t dwSectionSize = (pSectHdrs + nX)->SizeOfRawData == 0 ? (pSectHdrs + nX)->Misc.VirtualSize : (pSectHdrs + nX)->SizeOfRawData;

				if (dwSectionSize >= dwMinSize) {
					return nX;
				}
			}
			else {
				return nX;
			}
		}
	}

	return -1;
}