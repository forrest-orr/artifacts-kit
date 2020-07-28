               __  .__  _____               __     __   .__  __   
_____ ________/  |_|__|/ ____\____    _____/  |_  |  | _|__|/  |_ 
\__  \\_  __ \   __\  \   __\\__  \ _/ ___\   __\ |  |/ /  \   __\
 / __ \|  | \/|  | |  ||  |   / __ \\  \___|  |   |    <|  ||  |  
(____  /__|   |__| |__||__|  (____  /\___  >__|   |__|_ \__||__|  
     \/                           \/     \/            \/         

Malicious Memory Artifact Generator Kit v1.0 | Forrest Orr | 2020

REQUIRED
 
--alloc-type {dll-map-hollow|dll-load-hollow|txf-dll-map-hollow|private|mapped}

OPTIONAL

--payload-file <path>
--payload-type {PE|shellcode}
--exec-method {create-thread|call|ep-jmp-hook}
--stealth {wipe-headers|mirror-headers|rw-rx|dotnet|moat|peb-img-base}
--moat-size <size>
--hollow-dll-file <path>


--payload-file      The file containing either the shellcode or PE to be used as an implant. If this is
                    not supplied by the user, the specified region type will still be allocated but not
                    implanted with any code.
--payload-type      The type of code stored within the specified payload file. Must be a shellcode or
                    MZ PE. This parameter is required if a payload file is specified.
--alloc-type        The way in which the dynamic memory used to hold the payload implant should be
                    created.
                    
                    dll-map-hollow      A view of an image section generated from a DLL in System32.
                    dll-load-hollow     A DLL loaded via LoadLibrary from System32.
                    txf-dll-map-hollow  A view of an image section generated from a transacted DLL from
                                        System32 which has already been implanted with the payload.
                    private             A region of private memory allocated via NtAllocateVirtualMemory
                    mapped              A mapped view of a section derived from the Windows Page File.
--exec-method       The method with which to call to the payload code after it has been implanted in the
                    specified memory region.
                    
                    create-thread       Execute the payload using the CreateThread API.
                    call                Execute the payload using a regular CALL assembly instruction.
                    ep-jmp-hook         Execute the payload via an inline JMP from the process EXE
                                        entry point.
--stealth           Optional obfuscations to the allocated region.

                    wipe-headers        Overwrites the PE header of the payload in memory with 0's. Only
                                        valid for PE payloads.
                    mirror-headers      Preserves the original PE headers of a hollowed DLL after it is
                                        implanted with a payload PE file. Only valid for a PE payload
                                        using an image region type.
                    rw-rx               Rather than directly allocate the implant region with +RWX
                                        permissions, allocate it as +RW and set it to +RX afterward. Only
                                        valid for private and mapped region types.
                    dotnet              Only select DLLs with a .NET header during hollowing operations.
                                        Only valid for image region types.
                    moat                Pre-pad the allocated region proceeding the shellcode with 0s.
                                        By default 1MB of padding is used. Not valid for shellcode
                                        implants with hollowed DLLs. Cannot be used with TxF alloc type.
                    peb-img-base        Updates the image base field of the PEB to point to the newly
                                        allocated region.                   
--moat-size         The size of the data moat to generate prior to the payload implant. Only required if
                    the moat stealth option is specified. Default size of 1MB.
--hollow-dll-file   Manually specify the path of a DLL to use in conjunction with hollowing allocation
                    type. When this is not specified, a suitable DLL will randomly be selected from
                    the Windows directory or one of its subfolders.
					
EXAMPLES

Create a 32-bit shellcode implant within the .text section of a mapped 32-bit DLL image and execute it
using the CALL instruction:

	ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type dll-map-hollow
	
Create a 64-bit shellcode implant within a region of +RWX mapped page file memory at an offset +1MB
from its allocation base and execute it using the KERNEL32.DLL!CreateThread API:

	ArtifactsKit64.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode64.bin --alloc-type mapped --stealth moat
	
Create a 32-bit PE implant on top of the mapped image memory of a 32-bit DLL image while preserving its
original headers, bootstrap and execute the payload PE IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint with a CALL.

	ArtifactsKit32.exe --payload-type pe --payload-file Payloads\TestExe32.exe --alloc-type dll-map-hollow --stealth mirror-headers
	
Create a 64-bit PE implant within the mapped image memory of a modified TxF section of a 64-bit DLL
ie. phantom DLL hollowing and execute its IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint with a JMP hook from
the IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint of the artifact parent process:

	ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type txf-dll-map-hollow --exec-method ep-jmp-hook
	