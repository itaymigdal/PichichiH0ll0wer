import main
import params

proc NimMain() {.cdecl, importc.}

proc hi(): void {.stdcall, exportc, dynlib.} =
    NimMain()
    main()
        