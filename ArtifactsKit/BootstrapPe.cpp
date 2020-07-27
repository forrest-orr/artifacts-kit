/*
____________________________________________________________________________________________________
|                __  .__  _____               __     __   .__  __                                  |
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
#include <winternl.h>

#include "Allocation.h"

bool RefreshPeImgPermissions(uint8_t* pTargetPeBaseVa) {
	PIMAGE_DOS_HEADER pTargetPeDosHdr = (PIMAGE_DOS_HEADER)pTargetPeBaseVa;
	PIMAGE_FILE_HEADER pTargetPeFileHdr = (PIMAGE_FILE_HEADER)((uint8_t*)pTargetPeBaseVa + pTargetPeDosHdr->e_lfanew + sizeof(uint32_t));
	PIMAGE_OPTIONAL_HEADER pTargetPeOptHdr = (PIMAGE_OPTIONAL_HEADER)((uint8_t*)pTargetPeFileHdr + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pTargetPeSectHdrs = (PIMAGE_SECTION_HEADER)((uint8_t*)pTargetPeOptHdr + sizeof(IMAGE_OPTIONAL_HEADER));
	uint32_t dwOldProtect = 0, dwPermissions = PAGE_READONLY;

	if (VirtualProtect(pTargetPeBaseVa, pTargetPeOptHdr->SizeOfHeaders, dwPermissions, (PDWORD)&dwOldProtect)) {
		for (uint32_t dwX = 0; dwX < pTargetPeFileHdr->NumberOfSections; dwX++) {
			uint32_t dwSectionSize = ((dwX + 1) == pTargetPeFileHdr->NumberOfSections ? pTargetPeOptHdr->SizeOfImage : (pTargetPeSectHdrs + dwX + 1)->VirtualAddress) - (pTargetPeSectHdrs + dwX)->VirtualAddress;
			bool bMemWrite = false, bMemExecute = false;
#ifdef DEBUG
			Interface::Log(
				"[%d] Section %s:\r\n"
				"    Virtual address: 0x%08x\r\n"
				"    physical address: 0x%08x\r\n"
				"    Virtual size: 0x%08x\r\n"
				"    Physical size: 0x%08x\r\n"
				"    Next section? %s :: Size of image: 0x%p\r\n"
				"    Next section VA: 0x%08x\r\n",
				dwX,
				(pTargetPeSectHdrs + dwX)->Name,
				(pTargetPeSectHdrs + dwX)->VirtualAddress,
				(pTargetPeSectHdrs + dwX)->PointerToRawData,
				(pTargetPeSectHdrs + dwX)->Misc.VirtualSize,
				(pTargetPeSectHdrs + dwX)->SizeOfRawData,
				(dwX + 1) == pTargetPeFileHdr->NumberOfSections ? "yes" : "no",
				pTargetPeOptHdr->SizeOfImage,
				(dwX + 1) == pTargetPeFileHdr->NumberOfSections ? 0 : (pTargetPeSectHdrs + dwX + 1)->VirtualAddress);
#endif
			if (((pTargetPeSectHdrs + dwX)->Characteristics & IMAGE_SCN_MEM_WRITE)) {
				bMemWrite = true;
			}

			if (((pTargetPeSectHdrs + dwX)->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
				bMemExecute = true;
			}

			if (bMemWrite && !bMemExecute) {
#ifdef DEBUG
				printf("[%d] Section %s being set to +rw at 0x%p (%d:0x%08x bytes): 0x%p -> 0x%p\r\n", dwX, (pTargetPeSectHdrs + dwX)->Name, pTargetPeBaseVa + (pTargetPeSectHdrs + dwX)->VirtualAddress, dwSectionSize, dwSectionSize, (pTargetPeSectHdrs + dwX)->VirtualAddress, (pTargetPeSectHdrs + dwX)->VirtualAddress + dwSectionSize);
#endif
				dwPermissions = PAGE_READWRITE;
			}
			else if (bMemWrite && bMemExecute) {
#ifdef DEBUG
				printf("[%d] Section %s being set to +rwx at 0x%p (%d:0x%08x bytes): 0x%p -> 0x%p\r\n", dwX, (pTargetPeSectHdrs + dwX)->Name, pTargetPeBaseVa + (pTargetPeSectHdrs + dwX)->VirtualAddress, dwSectionSize, dwSectionSize, (pTargetPeSectHdrs + dwX)->VirtualAddress, (pTargetPeSectHdrs + dwX)->VirtualAddress + dwSectionSize);
#endif
				dwPermissions = PAGE_EXECUTE_READWRITE;
			}
			else if (!bMemWrite && bMemExecute) {
#ifdef DEBUG
				printf("[%d] Section %s being set to +rx at 0x%p (%d:0x%08x bytes): 0x%p -> 0x%p\r\n", dwX, (pTargetPeSectHdrs + dwX)->Name, pTargetPeBaseVa + (pTargetPeSectHdrs + dwX)->VirtualAddress, dwSectionSize, dwSectionSize, (pTargetPeSectHdrs + dwX)->VirtualAddress, (pTargetPeSectHdrs + dwX)->VirtualAddress + dwSectionSize);
#endif
				dwPermissions = PAGE_EXECUTE_READ;
			}
			else {
#ifdef DEBUG
				printf("[%d] Section %s being set to +r at 0x%p (%d:0x%08x bytes): 0x%p -> 0x%p\r\n", dwX, (pTargetPeSectHdrs + dwX)->Name, pTargetPeBaseVa + (pTargetPeSectHdrs + dwX)->VirtualAddress, dwSectionSize, dwSectionSize, (pTargetPeSectHdrs + dwX)->VirtualAddress, (pTargetPeSectHdrs + dwX)->VirtualAddress + dwSectionSize);
#endif
				dwPermissions = PAGE_READONLY;
			}

			if (!VirtualProtect(pTargetPeBaseVa + (pTargetPeSectHdrs + dwX)->VirtualAddress, dwSectionSize, dwPermissions, (PDWORD)&dwOldProtect)) {
				return false;
			}
		}
	}

	return true;
}

int32_t BootstrapImports(uint8_t* pMappedPeBase, bool bIatPreInit) {
	PIMAGE_DOS_HEADER pTargetPeDosHdr = (PIMAGE_DOS_HEADER)pMappedPeBase;
	PIMAGE_FILE_HEADER pTargetPeFileHdr = (PIMAGE_FILE_HEADER)((uint8_t*)pMappedPeBase + pTargetPeDosHdr->e_lfanew + sizeof(uint32_t));
	PIMAGE_OPTIONAL_HEADER pTargetPeOptHdr = (PIMAGE_OPTIONAL_HEADER)((uint8_t*)pTargetPeFileHdr + sizeof(IMAGE_FILE_HEADER));
	int32_t nImpCount = 0;

	//
	// Load the DLLs corresponding to the import table and fix each IAT entry.
	//

	if (pTargetPeOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
		uint8_t* pImpTableBaseVa = pMappedPeBase + pTargetPeOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

		for (PIMAGE_IMPORT_DESCRIPTOR pCurrentImgDesc = (PIMAGE_IMPORT_DESCRIPTOR)pImpTableBaseVa; pCurrentImgDesc->FirstThunk != 0; pCurrentImgDesc++) {
			const char* pCurrentImpModName = (const char*)(pMappedPeBase + pCurrentImgDesc->Name);
			HMODULE hCurrentImpMod = (bIatPreInit ? GetModuleHandleA(pCurrentImpModName) : LoadLibraryA(pCurrentImpModName)); // If the IAT has already been initialized do not use LoadLibraryA. This is essential in the case of a DLL re-basing itself from DllMain to avoid deadlocks.
#ifdef DEBUG
			printf("[*] Current import desc name: %s (loaded to 0x%p)\r\n", pCurrentImpModName, hCurrentImpMod);
#endif
			if (hCurrentImpMod != NULL) {
				//
				// Resolve the address of the INT (OriginalFirstThunk) if there is one for name resolution. Otherwise, use the IAT.
				//

				uint32_t dwSelectedImportTableRVA = (pCurrentImgDesc->OriginalFirstThunk ? pCurrentImgDesc->OriginalFirstThunk : pCurrentImgDesc->FirstThunk);
				PIMAGE_THUNK_DATA pCurrentNameImpThunk = (PIMAGE_THUNK_DATA)(pMappedPeBase + dwSelectedImportTableRVA);

				for (PIMAGE_THUNK_DATA pCurrentIatImpThunk = (PIMAGE_THUNK_DATA)(pMappedPeBase + pCurrentImgDesc->FirstThunk); pCurrentNameImpThunk->u1.AddressOfData != 0; pCurrentNameImpThunk++, pCurrentIatImpThunk++, nImpCount++) { // Walk the IAT thunk list in parallel to the name thunk list (they could in theory be the same).
					if (pCurrentNameImpThunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG) {
						uint16_t wOrdinal = IMAGE_ORDINAL(pCurrentNameImpThunk->u1.AddressOfData);
						uint64_t qwFuncAddress = (uint64_t)GetProcAddress(hCurrentImpMod, (LPCSTR)wOrdinal);
						uint32_t dwOldProtect = 0;

						if (VirtualProtect(pCurrentIatImpThunk, sizeof(IMAGE_THUNK_DATA), PAGE_READWRITE, (PDWORD)&dwOldProtect)) {
							pCurrentIatImpThunk->u1.Function = qwFuncAddress; // Patch IAT by resolving function address via ordinal. GetProcAddress will treat the string pointer as such. From MSN: "The function or variable name, or the function's ordinal value. If this parameter is an ordinal value, it must be in the low-order word; the high-order word must be zero."
							VirtualProtect(pCurrentIatImpThunk, sizeof(IMAGE_THUNK_DATA), dwOldProtect, (PDWORD)&dwOldProtect);
						}
					}
					else {
						uint16_t* pwHint = (uint16_t*)(pMappedPeBase + pCurrentNameImpThunk->u1.AddressOfData);
						const char* pFunctionName = (const char*)((uint8_t*)pwHint + sizeof(uint16_t)); // ANSI function name string comes after the hint WORD
						uint64_t qwFuncAddress = (uint64_t)GetProcAddress(hCurrentImpMod, pFunctionName);
						uint32_t dwOldProtect = 0;

						if (VirtualProtect(pCurrentIatImpThunk, sizeof(IMAGE_THUNK_DATA), PAGE_READWRITE, (PDWORD)&dwOldProtect)) {
							pCurrentIatImpThunk->u1.Function = qwFuncAddress; // Resolve the address of the imported function and patch it into the IAT of the virtually mapped PE image in memory.
							VirtualProtect(pCurrentIatImpThunk, sizeof(IMAGE_THUNK_DATA), dwOldProtect, (PDWORD)&dwOldProtect);
						}
#ifdef DEBUG
						printf("[*] Func: %s (address 0x%p)\r\n", pFunctionName, pCurrentIatImpThunk->u1.Function);
#endif
					}
				}
			}
		}
	}

	return nImpCount;
}

bool BootstrapPe(uint8_t* pTargetPeBuf, uint8_t** ppNewPeImageBase, uint8_t** ppNewPeEntryPoint, uint32_t* pdwNewSizeOfImage, uint8_t* pDestPeBuf, uint32_t dwDestPeBufSize, uint64_t qwImplantFlags, uint32_t dwMoatSize) {
	PIMAGE_DOS_HEADER pTargetPeDosHdr = (PIMAGE_DOS_HEADER)pTargetPeBuf;
	PIMAGE_FILE_HEADER pTargetPeFileHdr = (PIMAGE_FILE_HEADER)((uint8_t*)pTargetPeBuf + pTargetPeDosHdr->e_lfanew + sizeof(uint32_t));
	PIMAGE_OPTIONAL_HEADER pTargetPeOptHdr = (PIMAGE_OPTIONAL_HEADER)((uint8_t*)pTargetPeFileHdr + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pTargetPeSectHdrs = (PIMAGE_SECTION_HEADER)((uint8_t*)pTargetPeOptHdr + sizeof(IMAGE_OPTIONAL_HEADER));
	uint8_t* pNewPeBufBase = nullptr, * pNewPeImageBase = nullptr; // These two values can differ, for example when the PE is stored within a block of memory that is larger than needed at a set offset to avoid memory scanners.
	uint32_t dwTargetPeSize = pTargetPeOptHdr->SizeOfImage;
	uint32_t dwTotalNewPeBufSize = dwTargetPeSize + dwMoatSize;

	if (pDestPeBuf != nullptr) {
		pNewPeImageBase = pNewPeBufBase = pDestPeBuf;

		if ((qwImplantFlags & IMPLANT_FLAG_MOAT)) { // Moats are never initialized to any specific byte pattern. This means that from a VirtualAlloc'd zero-init region they will be 0's but for a hollowed DLL the moat will contain the content of the DLL up to the moat end offset (there will be 2 MZ in final image region)
			if (dwTotalNewPeBufSize > dwDestPeBufSize) {
				printf("... target PE with size of %d when combined with moat size of %d (total of %d bytes) is too large to be accomodated by specified destination buffer with size of %d\r\n", dwTargetPeSize, dwMoatSize, dwTotalNewPeBufSize, dwDestPeBufSize);
				return false;
			}

			pNewPeImageBase += dwMoatSize;
			printf("... selected base bootstrap moat address of 0x%p and PE image base of 0x%p\r\n", pNewPeBufBase, pNewPeImageBase);
		}
	}
	else {
#ifdef DEBUG
		printf("... failed to bootstrap PE: new PE buffer is a required parameter.\r\n", pNewPeImageBase);
#endif
		return false;
	}

	if (pNewPeBufBase != nullptr) {
		uint32_t dwOldProtect = 0;

		if (VirtualProtect(pNewPeImageBase, pTargetPeOptHdr->SizeOfImage, PAGE_READWRITE, (PDWORD)&dwOldProtect)) { // Key to note is that the SizeOfImage in the PE header is often modified (smaller than on disk) when wormhole regions are present. .NET PE altspace.dll is an example of this, however VirtualProtect still fails even though the size it is using should be smaller than the full view size. It is possible this is due to a characteristic of .NET
#ifdef DEBUG
			printf("[*] Temporarily changed permissions of bootstrap PE base 0x%p to +rw\r\n", pNewPeImageBase);
#endif
			if (!(qwImplantFlags & IMPLANT_FLAG_IMAGE_PRE_MAP)) {
				ZeroMemory(pNewPeImageBase, pTargetPeOptHdr->SizeOfImage); // Absolutely essential. In cases where an existing PE is being overwriten, virtual regions (which are assumed to be initialized to 0) will contain fragments of the old PE data.

				//
				// Virtually map the decrypted PE, aligning each section after copying its headers.
				//

				memcpy(pNewPeImageBase, pTargetPeBuf, pTargetPeOptHdr->SizeOfHeaders);

				for (uint32_t dwX = 0; dwX < pTargetPeFileHdr->NumberOfSections; dwX++) {
					uint32_t dwLargestCurrentSectionSize;

					if ((pTargetPeSectHdrs + dwX)->SizeOfRawData != 0) { // Handle .bss
						if (((pTargetPeSectHdrs + dwX)->SizeOfRawData < (pTargetPeSectHdrs + dwX)->Misc.VirtualSize)) {
							dwLargestCurrentSectionSize = (pTargetPeSectHdrs + dwX)->SizeOfRawData; // Some compilers will set VirtualSize to 0
						}
						else {
							dwLargestCurrentSectionSize = (pTargetPeSectHdrs + dwX)->Misc.VirtualSize;
						}

						memcpy(pNewPeImageBase + (pTargetPeSectHdrs + dwX)->VirtualAddress, pTargetPeBuf + (pTargetPeSectHdrs + dwX)->PointerToRawData, dwLargestCurrentSectionSize);
					}
				}
			}
			else {
				memcpy(pNewPeImageBase, pTargetPeBuf, dwTargetPeSize);
			}

			//
			// Load the DLLs corresponding to the import table and fix each IAT entry.
			//

			if (pTargetPeOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
				uint8_t* pImpTableBaseVa = pNewPeImageBase + pTargetPeOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

				for (PIMAGE_IMPORT_DESCRIPTOR pCurrentImgDesc = (PIMAGE_IMPORT_DESCRIPTOR)pImpTableBaseVa; pCurrentImgDesc->FirstThunk != 0; pCurrentImgDesc++) {
					const char* pCurrentImpModName = (const char*)(pNewPeImageBase + pCurrentImgDesc->Name);
					HMODULE hCurrentImpMod = ((qwImplantFlags & IMPLANT_FLAG_IAT_PRE_INIT) ? GetModuleHandleA(pCurrentImpModName) : LoadLibraryA(pCurrentImpModName)); // If the IAT has already been initialized do not use LoadLibraryA. This is essential in the case of a DLL re-basing itself from DllMain to avoid deadlocks.
#ifdef DEBUG
					printf("[*] Current import desc name: %s (loaded to 0x%p)\r\n", pCurrentImpModName, hCurrentImpMod);
#endif
					if (hCurrentImpMod != NULL) {
						//
						// Resolve the address of the INT (OriginalFirstThunk) if there is one for name resolution. Otherwise, use the IAT.
						//

						uint32_t dwSelectedImportTableRVA = (pCurrentImgDesc->OriginalFirstThunk ? pCurrentImgDesc->OriginalFirstThunk : pCurrentImgDesc->FirstThunk);
						PIMAGE_THUNK_DATA pCurrentNameImpThunk = (PIMAGE_THUNK_DATA)(pNewPeImageBase + dwSelectedImportTableRVA);

						for (PIMAGE_THUNK_DATA pCurrentIatImpThunk = (PIMAGE_THUNK_DATA)(pNewPeImageBase + pCurrentImgDesc->FirstThunk); pCurrentNameImpThunk->u1.AddressOfData != 0; pCurrentNameImpThunk++, pCurrentIatImpThunk++) { // Walk the IAT thunk list in parallel to the name thunk list (they could in theory be the same).
							if (pCurrentNameImpThunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG) {
								uint16_t wOrdinal = IMAGE_ORDINAL(pCurrentNameImpThunk->u1.AddressOfData);
								uint64_t qwFuncAddress = (uint64_t)GetProcAddress(hCurrentImpMod, (LPCSTR)wOrdinal);
								pCurrentIatImpThunk->u1.Function = qwFuncAddress; // Patch IAT by resolving function address via ordinal. GetProcAddress will treat the string pointer as such. From MSN: "The function or variable name, or the function's ordinal value. If this parameter is an ordinal value, it must be in the low-order word; the high-order word must be zero."
							}
							else {
								uint16_t* pwHint = (uint16_t*)(pNewPeImageBase + pCurrentNameImpThunk->u1.AddressOfData);
								const char* pFunctionName = (const char*)((uint8_t*)pwHint + sizeof(uint16_t)); // ANSI function name string comes after the hint WORD
								uint64_t qwFuncAddress = (uint64_t)GetProcAddress(hCurrentImpMod, pFunctionName);
								pCurrentIatImpThunk->u1.Function = qwFuncAddress; // Resolve the address of the imported function and patch it into the IAT of the virtually mapped PE image in memory.
#ifdef DEBUG
								printf("[*] Func: %s (address 0x%p)\r\n", pFunctionName, pCurrentIatImpThunk->u1.Function);
#endif
							}
						}
					}
				}
			}

			//
			// Fix base relocations to reflect new PE image base.
			//

			if (pTargetPeOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) { // Base relocations are not required but will be applied if they are present.
				uint8_t* pRelocTableBaseVa = pNewPeImageBase + pTargetPeOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
				PIMAGE_BASE_RELOCATION pCurrentRelocBlock = (PIMAGE_BASE_RELOCATION)pRelocTableBaseVa;

				for (uint32_t dwRelocationBufferOffset = 0; dwRelocationBufferOffset < pTargetPeOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size && pCurrentRelocBlock->SizeOfBlock != 0; dwRelocationBufferOffset += pCurrentRelocBlock->SizeOfBlock) {
					uint32_t dwCurrentRelocEntryCount = ((pCurrentRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t));
					uint16_t* pwCurrentRelocEntry = (uint16_t*)((uint8_t*)pCurrentRelocBlock + sizeof(IMAGE_BASE_RELOCATION));
#ifdef DEBUG
					printf("[*] Relocation chunk at base 0x%08x (%d items)\r\n", pCurrentRelocBlock->VirtualAddress, dwCurrentRelocEntryCount);
#endif
					for (uint32_t dwY = 0; dwY < dwCurrentRelocEntryCount; dwY++, pwCurrentRelocEntry++) {
#ifdef _WIN64
#define RELOC_FLAG_ARCH_AGNOSTIC IMAGE_REL_BASED_DIR64
#else
#define RELOC_FLAG_ARCH_AGNOSTIC IMAGE_REL_BASED_HIGHLOW
#endif
						if (((*pwCurrentRelocEntry >> 12) & RELOC_FLAG_ARCH_AGNOSTIC) == RELOC_FLAG_ARCH_AGNOSTIC) {
							uint32_t dwRelocEntryRefLocRva = (pCurrentRelocBlock->VirtualAddress + (*pwCurrentRelocEntry & 0x0FFF));
							uint8_t** ppRelocEntryRefLoc = (uint8_t**)((uint8_t*)pNewPeImageBase + dwRelocEntryRefLocRva);

							//
							// Patch the location in memory referencing an absolute address to reflect the new PE image base in memory.
							//
#ifdef DEBUG
							printf("[*] Patching value 0x%p at absolute address reference location 0x%p to ", *ppRelocEntryRefLoc, ppRelocEntryRefLoc);
#endif
#ifdef _WIN64
							* ppRelocEntryRefLoc = (*ppRelocEntryRefLoc - pTargetPeOptHdr->ImageBase) + (uint64_t)pNewPeImageBase;
#else
							* ppRelocEntryRefLoc = (*ppRelocEntryRefLoc - pTargetPeOptHdr->ImageBase) + (uint32_t)pNewPeImageBase;
#endif
#ifdef DEBUG
							printf("0x%p\r\n", *ppRelocEntryRefLoc);
#endif
						}
					}

					pCurrentRelocBlock = (PIMAGE_BASE_RELOCATION)((uint8_t*)pCurrentRelocBlock + pCurrentRelocBlock->SizeOfBlock);
				}
			}
			else {
#ifdef DEBUG
				printf("[!] No base relocations present.\r\n");
#endif
			}

			if (RefreshPeImgPermissions((uint8_t*)pNewPeImageBase)) {
#ifdef DEBUG
				printf("... successfully refreshed memory permissions on virtually bootstrapped PE.\r\n");
#endif
				* ppNewPeImageBase = pNewPeImageBase;
				*ppNewPeEntryPoint = (uint8_t*)(pNewPeImageBase + pTargetPeOptHdr->AddressOfEntryPoint);
				*pdwNewSizeOfImage = pTargetPeOptHdr->SizeOfImage;
				return true;
			}
		}
		else {
			printf("... failed to change permissions of %d bytes of PE memory to +RW\r\n", pTargetPeOptHdr->SizeOfImage);
		}
	}
	else {
#ifdef DEBUG
		printf("[-] Failed to allocate or identify memory for bootstrap PE base.\r\n");
#endif
	}

	return false;
}