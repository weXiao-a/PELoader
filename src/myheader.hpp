#ifndef _MYHEADER_H_
#define _MYHEADER_H_

#include<Windows.h>

IMAGE_DOS_HEADER myDosHeader;
IMAGE_NT_HEADERS myNTHeader;
IMAGE_FILE_HEADER myFileHeader;
IMAGE_OPTIONAL_HEADER myOptionHeader;
IMAGE_SECTION_HEADER* pmySectionHeader;
LONG e_lfanew;

#endif /* _MYHEADER_H_ */