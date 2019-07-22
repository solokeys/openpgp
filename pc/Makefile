CC=gcc
CFLAGS= -Wall -DLINUX 
PROGS= ccid

all:	${PROGS}

ccid:		usbip.c ccid.c 
		${CC} ${CFLAGS} usbip.c -c 
		${CC} ${CFLAGS} usbip.o ccid.c -o ccid

clean:
		rm -f ${PROGS} core core.* *.o temp.* *.out typescript*
