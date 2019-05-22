CC = g++

SRC := src/main.cpp src/util.c pc/device.c
INC := -I. -Ipc/ -Isrc/

OBJ=$(SRC:.c=.o)

CFLAGS=-O2 $(INC)

TARGET=main

all: $(OBJ)
	$(CC) $(CFLAGS) -o main $(OBJ)

clean:
	rm -rf $(OBJ) $(TARGET)
