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
int hw_reset_fs_and_reboot(bool reboot);

bool fileexist(char* name);
int readfile(char* name, uint8_t * buf, size_t max_size, size_t *size);
int writefile(char* name, uint8_t * buf, size_t size);
int deletefile(char* name);
int deletefiles(char* name);

int gen_random_device_callback(void *parameters, uint8_t *data, size_t size);
int gen_random_device(uint8_t * data, size_t size);

void ecdsa_init();
bool ecdsa_keygen(uint8_t *sk, size_t *sklen, uint8_t *pk, size_t *pklen, int curve);
size_t ecdsa_sign(uint8_t *sk, uint8_t *data, int len, uint8_t *sig, int curve);
size_t ecdsa_calc_public_key(uint8_t *sk, uint8_t *pk, int curve);
size_t ecdsa_ecdh_shared_secret(uint8_t *sk, uint8_t *pk, uint8_t *secret, int curve);

bool aes_encode_cbc(uint8_t *key, size_t keylen, uint8_t *data, uint8_t *encdata, size_t datalen);
bool aes_decode_cbc(uint8_t *key, size_t keylen, uint8_t *encdata, uint8_t *data, size_t datalen);

#endif
