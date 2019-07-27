CC=g++
CFLAGS= -Wall -DLINUX 
PROGS= ccid

all:	${PROGS}

ccid:		usbip.cpp ccid.cpp 
		${CC} ${CFLAGS} usbip.cpp -c 
		${CC} ${CFLAGS} usbip.o ccid.cpp -o ccid

clean:
		rm -f ${PROGS} *.o *.d
