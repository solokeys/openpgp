#ifndef _DEVICE_H_
#define _DEVICE_H_

#include <cstdint>
#include <cstdlib>

void ccid_init();

uint32_t ccid_recv(uint8_t * buf);

void ccid_send(uint8_t * buf, uint32_t sz);

bool fileexist(char* name);
int readfile(char* name, uint8_t * buf, size_t max_size, size_t *size);
int writefile(char* name, uint8_t * buf, size_t size);
int deletefile(char* name);
int deletefiles(char* name);
int hwreboot();

#endif
