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


INC = -I. -Ipc/ -Isrc/ -Ilibs/mbedtls/ -Ilibs/mbedtls/mbedtls/crypto/include/\
	-Ilibs/spiffs/ -Ilibs/spiffs/spiffs/src/

CPPFLAGS = -std=c++17 -O0 -Wall -g3 $(INC)
LDFLAGS = -Wl,-Bdynamic -lpthread

LIBS=libs/mbedtls/mbedtls.a

TARGET=main

include libs/spiffs/spiffs.mk

$(OBJ_DIR)/%.o:  
	$(CC) $(CPPFLAGS) -c -o $@ $(filter %/$(strip $(patsubst %.o, %.cpp, $(notdir $@))), $(SRC_FILES))

all:  $(SPIFFS_OBJ) $(OBJ_FILES) $(LIBS)
	$(CC) -o $(TARGET) $^ $(LDFLAGS)

include libs/mbedtls/mbedtls.mk

clean:
	$(RM) $(OBJ_FILES) $(DEP_FILES) $(TARGET) $(MBEDTLS_OBJ) $(MBEDTLS_A) $(SPIFFS_OBJ)
	
testpy:
	#cd ./pytest
	cd ~/solo/gnuk/tests; py.test-3 -x

testc:
	cd ./gtest; make clean; make all; ./ptest

testall: testc testpy
