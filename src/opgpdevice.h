#ifndef _OPGPDEVICE_H_
#define _OPGPDEVICE_H_

#include <cstdint>
#include <cstdlib>
#include <stdio.h>

#define OPGP_DEBUG

template <class ... Args>
constexpr void printf_device(const char *fmt, Args ... args) {
#ifdef OPGP_DEBUG
	printf(fmt, args...);
#endif
}
constexpr void printf_device(const char *fmt) {
#ifdef OPGP_DEBUG
    printf("%s", fmt);
#endif
}

#ifndef PUT_TO_SRAM2
#define PUT_TO_SRAM2 __attribute__((section(".sram2")))
#endif

void ccid_init();

uint32_t ccid_recv(uint8_t * buf);

void ccid_send(uint8_t * buf, uint32_t sz);

int hwinit();
int hwreboot();

bool fileexist(char* name);
int readfile(char* name, uint8_t * buf, size_t max_size, size_t *size);
int writefile(char* name, uint8_t * buf, size_t size);
int deletefile(char* name);
int deletefiles(char* name);

#endif
