CC = g++
RM = rm -rf

SRC = 	src/main.cpp \
		src/applet/applet.cpp\
		src/util.cpp \
		pc/device.cpp
		
INC = -I. -Ipc/ -Isrc/

OBJTMP = $(SRC:.c=.o)
OBJ = $(OBJTMP:.cpp=.o)

CPPFLAGS = -std=c++17 -O2 -Wall $(INC)

TARGET=main

all: $(OBJ)
	$(CC) -o main $(OBJ)

clean:
	$(RM) $(OBJ) $(TARGET)
	
testpy:
	#cd ./pytest
	cd ~/solo/gnuk/tests; py.test-3 -x

testc:
	cd ./gtest; make clean; make all; ./ptest

testall: testc testpy
