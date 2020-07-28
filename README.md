## PELoader
PE structure loader.

## Download
```
git clone git@github.com:StepfenShawn/PELoader.git
```

## How to complie
```
cd src/
make
```

## How to run
```
cd bin\
PELoarder.exe "test.exe"
```
Result:
```
================IMAGE_DOS_HEADER================
WORD e_magic:                           5A4D
DOWRD e_lfaner:                         000000E8

================IMAGE_NT_HEADER================
DWORD Signature:                        00004550

================IMAGE_FILE_HEADER================
WORD Machine:                           014C
WORD NumberOfSection:                   0004
DWORD TimeDateStamp:                    5367EC5B
DWORD pointerToSymbolTable              00000000
DWORD NumberOfSymbols:                  00000000
WORD SizeOfOptionHeader:                00E0
WORD Characteristics:                   0103

================IMAGE_OPTION_HEADER================
WORD Magic:                                     010B
BYTE MajorLinkerVersion:                        08
BYTE MinorLinkerVersion:                        00
DWORD SizeOfCode;                               00001800
DWORD SizeOfInitializedData:                    00000000
 DWORD SizeOfUninitializedData                  00000000
DWORD AddressOfEntryPoint:                      00000000
DWORD BaseOfCode:                               00000000
DWORD ImageBase:                                00000000
DWORD SectionAlignmen:                          00000000
DWORD FileAlignment:                            00000000
WORD MajorOperatingSystemVersion:               0000
WORD MinorOperatingSystemVersion:               0000
WORD MajorImageVersion:                         0000
WORD MinorImageVersion:                         0000
WORD MajorSubsystemVersion:                     0000
WORD MinorSubsystemVersion:                     0000
DWORD Win32VersionValue:                        00000000
DWORD SizeOfImage:                              00000000
DWORD SizeOfHeaders:                            00000000
DWORD CheckSum:                                 00000000
WORD Subsystem:                                 0000
WORD DllCharacteristics:                        0000
DWORD SizeOfStackReserve:                       00000000
DWORD SizeOfStackCommit:                        00000000
DWORD SizeOfHeapReserve:                        00000000
DWORD SizeOfHeapCommit:                         00000000
DWORD LoaderFlags:                                  00000000
DWORD NumberOfRvaAndSizes :                     00000000

================IMAGE_OPTIONAL_HEADER================
BYTE Name:
:DWORD PhysicalAddress                  00000000
:DWORD VirtualSize                      00000000
:DWORD VirtualAddress                   00000000
:DWORD SizeOfRawData                    00000000
:DWORD PointerToRawData                 60000020
:DWORD PointerToRelocations             6164722E
:DWORD PointerToLinenumbers             00006174
:WORD NumberOfRelocations               0BA4
:WORD NumberOfLinenumbers               0000
:DWORD Characteristics                  00003000

BYTE Name:
:DWORD PhysicalAddress                  00000000
:DWORD VirtualSize                      00000000
:DWORD VirtualAddress                   00000000
:DWORD SizeOfRawData                    00000000
:DWORD PointerToRawData                 40000040
:DWORD PointerToRelocations             7461642E
:DWORD PointerToLinenumbers             00000061
:WORD NumberOfRelocations               0394
:WORD NumberOfLinenumbers               0000
:DWORD Characteristics                  00004000

BYTE Name:
:DWORD PhysicalAddress                  00000000
:DWORD VirtualSize                      00000000
:DWORD VirtualAddress                   00000000
:DWORD SizeOfRawData                    00000000
:DWORD PointerToRawData                 C0000040
:DWORD PointerToRelocations             7273722E
:DWORD PointerToLinenumbers             00000063
:WORD NumberOfRelocations               0A38
:WORD NumberOfLinenumbers               0000
:DWORD Characteristics                  00005000

BYTE Name:
:DWORD PhysicalAddress                  00000000
:DWORD VirtualSize                      00000000
:DWORD VirtualAddress                   00000000
:DWORD SizeOfRawData                    00000000
:DWORD PointerToRawData                 40000040
:DWORD PointerToRelocations             00000000
:DWORD PointerToLinenumbers             00000000
:WORD NumberOfRelocations               0000
:WORD NumberOfLinenumbers               0000
:DWORD Characteristics                  00000000
```

## Contribution
Welcome to pull a request!  

## License
MIT License  
