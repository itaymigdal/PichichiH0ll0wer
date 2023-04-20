
# PichichiH0ll0wer

<p align="center">
  <img alt="Pichichi" src="/assets/pichichi.png">
</p>

- [PichichiH0ll0wer](#pichichih0ll0wer)
- [About](#about)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Credits](#credits)

# About

*--== Process hollowing loader written in Nim for PEs only ==--*

I built PichichiH0ll0wer to learn and contribute, sure. but also because I'm quite tired of shellcodes everywhere. 
Loading PEs might be less evasive, I know, but it's still efficient and more convenient than fighting to turn your PE payload into a shellcode each time (which not always works smoothly).
Also, PichichiH0ll0wer has some features to protect your payload.
I may add some more injection techniques and features at the future.

![](/assets/ui.png)

# Features
- Configurable builder
- Payload encrypted and compressed in the hollow loader
- Simple hollowing (using Windows API) and direct syscalls hollowing using NimlineWhispers2
- Can build EXE / DLL hollow loaders
- Can block unsigned microsoft DLLs from being loaded to the hollowed process
- Obfuscated sleep using useless calculations

# Installation
Built with Nim 1.6.12, should be run on Windows only.
```
nimble install winim ptr_math nimprotect zip argparse
```

# Usage

```
Usage:
   [options] exe_file injection_method

Arguments:
  exe_file         Exe file to load
  injection_method Injection method

        1 - Simple hollowing
        2 - Syscalls hollowing (using NimlineWhispers2)

Options:
  -h, --help
  -s, --sponsor=SPONSOR      Sponsor path to hollow (default: self hollowing)
  -a, --args=ARGS            Command line arguments to append to the hollowed process
  -f, --format=FORMAT        PE hollower format Possible values: [exe, dll] (default: exe)
  -e, --export=EXPORT        DLL export name (relevant only for Dll format) (default: DllRegisterServer)
  -b, --block                Block unsigned Microsoft Dlls in the hollowed process
  -t, --sleep=SLEEP          Number of seconds to sleep before hollowing (default: 0)
  -d, --debug                Compile as debug instead of release (loader is verbose)
```

# Credits
- [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim)
- [NimlineWhispers2](https://github.com/ajpc500/NimlineWhispers2)
- [Hasherezade code and notes](https://github.com/hasherezade/libpeconv/tree/master/run_pe)


  
