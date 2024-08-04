import winim
import strutils
import nimprotect


proc createMailslot*(mailslotPath: string): HANDLE =
    let mailslotHandle = CreateMailslot(mailslotPath, 0, 0, nil)
    if mailslotHandle == INVALID_HANDLE_VALUE:
        if not defined(release): echo protectString("[-] Failed to create mailslot: "), GetLastError()
        return 0
    return mailslotHandle


proc readMailslot*(mailslotHandle: HANDLE): string =
    var
        bytesRead: DWORD
        messageBuffer = newSeq[char](256)
    discard ReadFile(
        mailslotHandle, 
        cast[LPVOID](addr messageBuffer[0]), 
        cast[DWORD](messageBuffer.len), 
        addr bytesRead, 
        nil
        )
    if bytesRead == 0:
        if not defined(release): echo protectString("[-] Failed to read from mailslot: "), GetLastError()
        return ""
    return messageBuffer[0 .. int(bytesRead)-1].join("")


proc writeMailslot*(mailslotPath: string, message: string): bool =
    # Write to the mailslot
    let mailslotHandle = CreateFile(mailslotPath, GENERIC_WRITE, FILE_SHARE_READ, nil, OPEN_EXISTING, 0, 0)
    if mailslotHandle == INVALID_HANDLE_VALUE:
        if not defined(release): echo protectString("[-] Failed to open mailslot for writing: "), GetLastError()
        return false
    var lpNumberOfBytesWritten: DWORD
    discard WriteFile(
        mailslotHandle, 
        cast[LPVOID](cstring(message)), 
        cast[DWORD](message.len),
        cast[LPDWORD](addr lpNumberOfBytesWritten), 
        nil
        )
    if lpNumberOfBytesWritten == 0:
        if not defined(release): echo protectString("[-] Failed to write to mailslot: "), GetLastError()
        return false
    CloseHandle(mailslotHandle)
    return true


## Example ##
when isMainModule:

    const mailslotPath = "\\\\.\\mailslot\\example_mailslot"

    # Create a mailslot
    let mailslotHandle = createMailslot(mailslotPath)
    
    # Write to the mailslot
    discard writeMailslot(mailslotPath, "Hello from the sender!")

    # Read from the mailslot
    let message = readMailslot(mailslotHandle)
    echo "Received message: ", message