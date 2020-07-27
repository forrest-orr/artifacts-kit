IMAGE_SECTION_HEADER* GetContainerSectHdr(IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHeader, uint64_t qwRVA);
void* GetPAFromRVA(uint8_t* pPeBuf, IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHdrs, uint64_t qwRVA);
bool CheckRelocRange(uint8_t* pRelocBuf, uint32_t dwRelocBufSize, uint32_t dwStartRVA, uint32_t dwEndRVA);
int32_t GetCodeSection(IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pSectHdrs, uint32_t dwMinSize);