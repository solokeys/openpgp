#ifndef _DEVICE_H_
#define _DEVICE_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void ccid_init();

uint32_t ccid_recv(uint8_t * buf);

void ccid_send(uint8_t * buf, uint32_t sz);


#ifdef __cplusplus
}
#endif

#endif
