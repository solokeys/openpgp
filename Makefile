CC = g++
RM = rm -rf

SRC = 	src/main.cpp \
		src/applet/applet.cpp\
		src/util.c \
		pc/device.c
		
INC = -I. -Ipc/ -Isrc/

OBJTMP = $(SRC:.c=.o)
OBJ = $(OBJTMP:.cpp=.o)

CPPFLAGS = -O2 -Wall $(INC)

TARGET=main

all: $(OBJ)
	$(CC) -o main $(OBJ)

clean:
	$(RM) $(OBJ) $(TARGET)
