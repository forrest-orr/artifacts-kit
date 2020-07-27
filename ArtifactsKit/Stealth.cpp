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

#include "PEB.h"

bool MirrorPeHdrs(uint8_t* pAuthenticPeBuf, uint8_t* pNewPeBuf) {
	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pAuthenticPeBuf;

	if (*(uint16_t*)&pAuthenticPeBuf[0] == 'ZM') {
		IMAGE_NT_HEADERS* pNtHdrs = (IMAGE_NT_HEADERS*)(pAuthenticPeBuf + pDosHdr->e_lfanew);
		if (pNtHdrs->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC) {
			uint32_t dwOldProtect = 0;
			uint32_t dwHdrSize = pNtHdrs->OptionalHeader.SizeOfHeaders;
			VirtualProtect(pNewPeBuf, dwHdrSize, PAGE_READWRITE, (PDWORD)&dwOldProtect);
			memcpy(pNewPeBuf, pAuthenticPeBuf, dwHdrSize);
			VirtualProtect(pNewPeBuf, dwHdrSize, PAGE_READONLY, (PDWORD)&dwOldProtect);
			return true;
		}
	}

	return false;
}

bool WipePeHdrs(uint8_t* pPeBuf) {
	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pPeBuf;

	if (*(uint16_t*)&pPeBuf[0] == 'ZM') {
		IMAGE_NT_HEADERS* pNtHdrs = (IMAGE_NT_HEADERS*)(pPeBuf + pDosHdr->e_lfanew);
		if (pNtHdrs->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC) {
			uint32_t dwOldProtect = 0;
			uint32_t dwHdrSize = pNtHdrs->OptionalHeader.SizeOfHeaders;
			VirtualProtect(pPeBuf, dwHdrSize, PAGE_READWRITE, (PDWORD)&dwOldProtect);
			ZeroMemory(pPeBuf, dwHdrSize);
			VirtualProtect(pPeBuf, dwHdrSize, PAGE_READONLY, (PDWORD)&dwOldProtect);
			return true;
		}
	}

	return false;
}

void *UpdatePebImageBase(void *pNewImageBase) {
	void* pOriginalImageBase;
#ifdef _WIN64
	PEB64* pPEB;
	pPEB = (PEB64 *)__readgsqword(0x60);
	pOriginalImageBase = reinterpret_cast<void *>(pPEB->ImageBaseAddress);
	pPEB->ImageBaseAddress = reinterpret_cast<QWORD>(pNewImageBase);
#else
	PEB32* pPEB;
	__asm {
		Mov Eax, Dword Ptr Fs : [0x30]
		Mov[pPEB], Eax
	}
	pOriginalImageBase = reinterpret_cast<void*>(pPEB->ImageBaseAddress);
	pPEB->ImageBaseAddress = reinterpret_cast<uint32_t>(pNewImageBase);
#endif
	return pOriginalImageBase;
}