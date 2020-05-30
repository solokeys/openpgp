/*
 *
 * (c) 2020 Merlok
 *
 *
 */

#ifndef I15_ADDON_C
#define I15_ADDON_C

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#include "bearssl.h"

void br_i15_print_int(const char *name, const uint16_t *x);
uint32_t br_i15_sub_uint(uint16_t *a, const uint32_t b, uint32_t ctl);
uint32_t br_i15_add_uint(uint16_t *a, const uint32_t b, uint32_t ctl);


bool br_rsa_deduce_crt(uint8_t *buffer, br_rsa_private_key *sk, uint8_t *exp);


#ifdef __cplusplus
}
#endif

#endif // I15_ADDON_C
