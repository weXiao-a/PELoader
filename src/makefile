TOP = ..
TARGET = $(TOP)/bin/PEloader

ifeq (Windows_NT, $(OS))
TARGET := $(TARGET).exe
endif

$(TARGET) :
	mkdir -p "$$(dirname $(TARGET))"
	g++ main.cpp  -o $(TARGET)