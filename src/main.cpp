#include <iostream>

#ifdef WIN32
#include "myheader.hpp"
#else
std::cout<<"Your system don't support this program!"<<std::endl;
exit();
#endif

#ifdef WIN32
#define fopen_s(pFile,filename,mode) ((*(pFile))=fopen((filename),  (mode)))==NULL
#endif

int main(int argc, char* argv[])
{
	FILE* pfile;
	errno_t err;
	DWORD fileSize = 0;

	if(argc <= 1)
    {
        std::cout<<"No file input!"<<std::endl;
        return 0;
    }

	if ((err = fopen_s(&pfile, argv[1], "r"))!= 0)
	{
		std::cout<<"can not open the file!"<<std::endl;;
		getchar();
	}


	std::cout<<"================IMAGE_DOS_HEADER================"<<std::endl;
	fread(&myDosHeader,1 ,sizeof(IMAGE_DOS_HEADER), pfile);
	if (myDosHeader.e_magic!=0x5A4D)
	{
		fclose(pfile);
		exit(0);
	}
	printf("WORD e_magic:				%04X\n", myDosHeader.e_magic);
	printf("DOWRD e_lfaner:				%08X\n\n", myDosHeader.e_lfanew);
	e_lfanew = myDosHeader.e_lfanew;


	std::cout<<"================IMAGE_NT_HEADER================"<<std::endl;
	fseek(pfile, e_lfanew, SEEK_SET);
	fread(&myNTHeader, 1, sizeof(IMAGE_NT_HEADERS), pfile);
	if (myNTHeader.Signature != 0x4550)
	{
		fclose(pfile);
		exit(0);
	}
	printf("DWORD Signature:			%08X\n\n",myNTHeader.Signature);


	std::cout<<"================IMAGE_FILE_HEADER================"<<std::endl;
	printf("WORD Machine:				%04X\n", myNTHeader.FileHeader.Machine);
	printf("WORD NumberOfSection:			%04X\n", myNTHeader.FileHeader.NumberOfSections);
	printf("DWORD TimeDateStamp:			%08X\n", myNTHeader.FileHeader.TimeDateStamp);
	printf("DWORD pointerToSymbolTable		%08X\n", myNTHeader.FileHeader.PointerToSymbolTable);
	printf("DWORD NumberOfSymbols:			%08X\n", myNTHeader.FileHeader.NumberOfSymbols);
	printf("WORD SizeOfOptionHeader:		%04X\n", myNTHeader.FileHeader.SizeOfOptionalHeader);
	printf("WORD Characteristics:			%04X\n\n", myNTHeader.FileHeader.Characteristics);


	std::cout<<"================IMAGE_OPTION_HEADER================"<<std::endl;
	printf("WORD Magic;					%04X\n", myNTHeader.OptionalHeader.Magic);
	printf("BYTE MajorLinkerVersion:			%02X\n", myNTHeader.OptionalHeader.MajorLinkerVersion);
	printf("BYTE MinorLinkerVersion:			%02X\n",myNTHeader.OptionalHeader.MinorLinkerVersion);
	printf("DWORD SizeOfCode;				%08X\n", myNTHeader.OptionalHeader.SizeOfCode);
	printf("DWORD SizeOfInitializedData:			%08X\n", myNTHeader.OptionalHeader.SizeOfInitializedData);
	printf(" DWORD SizeOfUninitializedData			%08X\n", myNTHeader.OptionalHeader.SizeOfUninitializedData);
	printf("DWORD AddressOfEntryPoint:			%08X\n", myNTHeader.OptionalHeader.AddressOfEntryPoint);
	printf("DWORD BaseOfCode:				%08X\n", myNTHeader.OptionalHeader.BaseOfCode);
	printf("DWORD ImageBase:				%08X\n", myNTHeader.OptionalHeader.ImageBase);
	printf("DWORD SectionAlignmen:				%08X\n", myNTHeader.OptionalHeader.SectionAlignment);
	printf("DWORD FileAlignment:				%08X\n", myNTHeader.OptionalHeader.FileAlignment);
	printf("WORD MajorOperatingSystemVersion:		%04X\n", myNTHeader.OptionalHeader.MajorOperatingSystemVersion);
	printf("WORD MinorOperatingSystemVersion:		%04X\n", myNTHeader.OptionalHeader.MinorOperatingSystemVersion);
	printf("WORD MajorImageVersion:				%04X\n", myNTHeader.OptionalHeader.MajorImageVersion);
	printf("WORD MinorImageVersion:				%04X\n", myNTHeader.OptionalHeader.MinorImageVersion);
	printf("WORD MajorSubsystemVersion:			%04X\n", myNTHeader.OptionalHeader.MajorSubsystemVersion);
	printf("WORD MinorSubsystemVersion:			%04X\n", myNTHeader.OptionalHeader.MinorSubsystemVersion);
	printf("DWORD Win32VersionValue:			%08X\n", myNTHeader.OptionalHeader.Win32VersionValue);
	printf("DWORD SizeOfImage:				%08X\n", myNTHeader.OptionalHeader.SizeOfImage);
	printf("DWORD SizeOfHeaders:				%08X\n", myNTHeader.OptionalHeader.SizeOfHeaders);
	printf("DWORD CheckSum:					%08X\n", myNTHeader.OptionalHeader.CheckSum);
	printf("WORD Subsystem:					%04X\n", myNTHeader.OptionalHeader.Subsystem);
	printf("WORD DllCharacteristics:			%04X\n", myNTHeader.OptionalHeader.DllCharacteristics);
	printf("DWORD SizeOfStackReserve:			%08X\n", myNTHeader.OptionalHeader.SizeOfStackReserve);
	printf("DWORD SizeOfStackCommit:			%08X\n", myNTHeader.OptionalHeader.SizeOfStackCommit);
	printf("DWORD SizeOfHeapReserve:			%08X\n", myNTHeader.OptionalHeader.SizeOfHeapReserve);
	printf("DWORD SizeOfHeapCommit:				%08X\n", myNTHeader.OptionalHeader.SizeOfHeapCommit);
	printf("DWORD LoaderFlags:				    %08X\n", myNTHeader.OptionalHeader.LoaderFlags);
	printf("DWORD NumberOfRvaAndSizes :			%08X\n\n", myNTHeader.OptionalHeader.NumberOfRvaAndSizes);


	std::cout<<"================IMAGE_OPTIONAL_HEADER================"<<std::endl;
	pmySectionHeader = (IMAGE_SECTION_HEADER*)calloc(myNTHeader.FileHeader.NumberOfSections, sizeof(IMAGE_SECTION_HEADER));
	fseek(pfile, (e_lfanew + sizeof(IMAGE_NT_HEADERS)), SEEK_SET);
	fread(pmySectionHeader, sizeof(IMAGE_SECTION_HEADER), myNTHeader.FileHeader.NumberOfSections, pfile);
	for (int i = 0; i < myNTHeader.FileHeader.NumberOfSections; i++, pmySectionHeader++)
	{
		printf("BYTE Name:				        %s\n", pmySectionHeader->Name);
		printf(":DWORD PhysicalAddress			%08X\n", pmySectionHeader->Misc.PhysicalAddress);
		printf(":DWORD VirtualSize			%08X\n", pmySectionHeader->Misc.VirtualSize);
		printf(":DWORD VirtualAddress			%08X\n", pmySectionHeader->VirtualAddress);
		printf(":DWORD SizeOfRawData			%08X\n", pmySectionHeader->SizeOfRawData);
		printf(":DWORD PointerToRawData			%08X\n", pmySectionHeader->PointerToRawData);
		printf(":DWORD PointerToRelocations		%08X\n", pmySectionHeader->PointerToRelocations);
		printf(":DWORD PointerToLinenumbers		%08X\n", pmySectionHeader->PointerToLinenumbers);
		printf(":WORD NumberOfRelocations		%04X\n", pmySectionHeader->NumberOfRelocations);
		printf(":WORD NumberOfLinenumbers		%04X\n", pmySectionHeader->NumberOfLinenumbers);
		printf(":DWORD Characteristics			%08X\n\n", pmySectionHeader->Characteristics);

	}
	pmySectionHeader = NULL;
	free(pmySectionHeader);
	fclose(pfile);
	getchar();
	return 0;
}