typedef LONG(__stdcall* NtCreateSection_t)(HANDLE*, ULONG, void*, LARGE_INTEGER*, ULONG, ULONG, HANDLE);
typedef LONG(__stdcall* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS(__stdcall* NtCreateTransaction_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING);

enum class Payload_t {
	Invalid = 0,
	None,
	PE,
	Shellcode
};

uint8_t* DynamicAllocImplant(HANDLE hProcess, bool bRemoteApi, uint8_t* pPayloadBuf, uint32_t dwPayloadSize, Payload_t SelectedPayloadType, uint64_t qwImplantFlags, uint8_t** ppAllocatedRegion, uint32_t dwMoatSize);
bool HollowDllScan(uint8_t** ppMapBuf, uint64_t* pqwMapBufSize, const uint8_t* pPayloadBuf, uint32_t dwPayloadBufSize, uint8_t** ppEntryPoint, Payload_t SelectedPayloadType, uint64_t qwImplantFlags, uint32_t dwMoatSize);
bool HollowDllImplant(const wchar_t* DllFilePath, uint8_t** ppMapBuf, uint64_t* pqwMapBufSize, const uint8_t* pPayloadBuf, uint32_t dwPayloadBufSize, uint8_t** ppEntryPoint, Payload_t SelectedPayloadType, uint64_t qwImplantFlags, uint32_t dwMoatSize);
bool CheckRelocRange(uint8_t* pRelocBuf, uint32_t dwRelocBufSize, uint32_t dwStartRVA, uint32_t dwEndRVA);
void* GetPAFromRVA(uint8_t* pPeBuf, IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHdrs, uint64_t qwRVA);

#define IMPLANT_FLAG_RW_RX 0x1
#define IMPLANT_FLAG_WIPE_PE_HDR 0x2
#define IMPLANT_FLAG_MEM_PRIVATE 0x4
#define IMPLANT_FLAG_MEM_MAPPED 0x8
#define IMPLANT_FLAG_MIRROR_PE_HDR 0x10
#define IMPLANT_FLAG_TXF 0x20
#define IMPLANT_FLAG_ISOLATED_MAP 0x40
#define IMPLANT_FLAG_DOTNET 0x80
#define IMPLANT_FLAG_PEB_IMAGE_BASE 0x100
//#define IMPLANT_FLAG_CFG_DISABLED 0x200
#define IMPLANT_FLAG_MOAT 0x400
#define IMPLANT_FLAG_IMAGE_PRE_MAP 0x800
#define IMPLANT_FLAG_IAT_PRE_INIT 0x1000

#define DEFAULT_MOAT_SIZE 0xF4240 // 1MB