CC = g++
RM = rm -rf

rwildcard=$(wildcard $1$2) $(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2))

OBJ_DIR := ./obj
SRC_DIRS := ./pc \
			./src \
			./src/applets \
			./src/applets/openpgp
SRC_FILES := $(sort $(foreach var, $(SRC_DIRS), $(wildcard $(var)/*.cpp)))
OBJ_FILES := $(patsubst %.cpp, $(OBJ_DIR)/%.o, $(notdir $(SRC_FILES)))
DEP_FILES = $(OBJ_FILES:.o=.d)

INC = -I. -Ipc/ -Isrc/

CPPFLAGS = -std=c++17 -O2 -Wall $(INC)

TARGET=main

$(OBJ_DIR)/%.o:  
	$(CC) $(CPPFLAGS) -c -o $@ $(filter %/$(strip $(patsubst %.o, %.cpp, $(notdir $@))), $(SRC_FILES))

all:  $(OBJ_FILES)
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	@echo I $(SRC_FILES) I
	@echo I $(OBJ_FILES) I
	$(RM) $(OBJ_FILES) $(DEP_FILES) $(TARGET)
	
testpy:
	#cd ./pytest
	cd ~/solo/gnuk/tests; py.test-3 -x

testc:
	cd ./gtest; make clean; make all; ./ptest

testall: testc testpy
