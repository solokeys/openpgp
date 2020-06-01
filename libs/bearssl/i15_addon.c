/*
 *
 * (c) 2020 Merlok
 *
 *
 */

#include "i15_addon.h"

#include <stdio.h>
#include "inner.h"

void br_i15_print_int(const char *name, const uint16_t *x) {
    unsigned char tmp[1024];
    size_t u, len;
    len = (x[0] - (x[0] >> 4) + 7) >> 3;
    br_i15_encode(tmp, len, x);
    printf("%s [%d] = ", name, len);
    for (u = 0; u < len; u ++) {
        printf("%02X", tmp[u]);
    }
    printf("\n");
}

uint32_t br_i15_sub_uint(uint16_t *a, const uint32_t b, uint32_t ctl) {
    uint32_t cc;
    size_t u, m;

    cc = 0;
    m = (a[0] + 31) >> 4;
    for (u = 1; u < m; u ++) {
        uint32_t aw, bw, naw;

        aw = a[u];
        bw = 0;
        if (u == 1) bw = b & 0x7FFFU;
        if (u == 2) bw = (b >> 15) & 0x7FFFU;
        if (u == 3) bw = (b >> 30) & 0x7FFFU;

        naw = aw - bw - cc;
        cc = naw >> 31;
        a[u] = MUX(ctl, naw & 0x7FFF, aw);
    }
    return cc;
}

uint32_t br_i15_add_uint(uint16_t *a, const uint32_t b, uint32_t ctl) {
    uint32_t cc;
    size_t u, m;

    cc = 0;
    m = (a[0] + 31) >> 4;
    for (u = 1; u < m; u ++) {
        uint32_t aw, bw, naw;

        aw = a[u];
        bw = 0;
        if (u == 1) bw = b & 0x7FFFU;
        if (u == 2) bw = (b >> 15) & 0x7FFFU;
        if (u == 3) bw = (b >> 30) & 0x7FFFU;

        naw = aw + bw + cc;
        cc = naw >> 15;
        a[u] = MUX(ctl, naw & 0x7FFF, aw);
    }
    return cc;
}

inline uint16_t br_i15_size_bitlen(uint16_t *a) {
    return a[0];
}

inline uint32_t br_i15_size_int_u16(uint16_t *a) {
    return (br_i15_size_bitlen(a) + 31) >> 4;
}

inline uint32_t br_i15_size_u16(uint16_t *a) {
    return br_i15_size_int_u16(a) + 1; // plus length u16
}

void br_i15_u32(uint16_t *x, uint16_t bit_len, uint32_t val) {
    br_i15_zero(x, bit_len);
    x[1] = val & 0x7FFF;
    x[2] = (val >> 15) & 0x7FFF;
    x[3] = val >> 30;
}

void br_i15_one(uint16_t *x, uint16_t bit_len) {
    br_i15_u32(x, bit_len, 1);
}

// from rsa_i15_keygen.c
static void
bufswap(void *b1, void *b2, size_t len)
{
    size_t u;
    unsigned char *buf1, *buf2;

    buf1 = b1;
    buf2 = b2;
    for (u = 0; u < len; u ++) {
        unsigned w;

        w = buf1[u];
        buf1[u] = buf2[u];
        buf2[u] = w;
    }
}

size_t br_rsa_i15_compute_privexp_int_u16(uint16_t *d, const br_rsa_private_key *sk, uint32_t e) {
    uint8_t temp[512 + 10]; // 512 - RSA4096
    size_t dlen = br_rsa_i15_compute_privexp(temp, sk, e);
    br_i15_decode(d, temp, dlen);
    return dlen;
}

bool br_rsa_deduce_crt(uint8_t *buffer, br_rsa_private_key *sk, uint8_t *exp) {

    uint32_t exp32 = br_dec32be(exp);

    // size variants:
    // 1. d (2x) p or q  = 4 * 142
    // 2. p and q and 4 bigints
    uint16_t tmp[1000]; // TODO: add calc here
    memset(tmp, 0, sizeof(tmp));

    // calc private exponent d
    uint16_t *d = tmp;
    if (br_rsa_i15_compute_privexp_int_u16(d, sk, exp32) == 0)
        return false;
    size_t dlen = br_i15_size_u16(d);

    // get p
    uint16_t *p = tmp + dlen + 2;
    br_i15_decode(p, sk->p, sk->plen);
    size_t plen = br_i15_size_u16(p);

    // calc dp
    uint16_t *dp = p + plen;
    br_i15_sub_uint(p, 1, 1);
    br_i15_reduce(dp, d, p);

    // save dp
    sk->dp = &buffer[0];
    sk->dplen = sk->plen;
    br_i15_encode(sk->dp, sk->dplen, dp);

    // get q
    uint16_t *q = p;
    br_i15_decode(q, sk->q, sk->qlen);
    size_t qlen = br_i15_size_u16(q);

    // calc dq
    uint16_t *dq = q + qlen;
    br_i15_sub_uint(q, 1, 1);
    br_i15_reduce(dq, d, q);

    // calc dq
    sk->dq = &buffer[sk->dplen];
    sk->dqlen = sk->plen;
    br_i15_encode(sk->dq, sk->dqlen, dq);

    // get p and q
    memset(tmp, 0, sizeof(tmp));
    p = tmp;
    br_i15_decode(p, sk->p, sk->plen);
    plen = br_i15_size_u16(p);
    q = tmp + plen + 2;
    br_i15_decode(q, sk->q, sk->qlen);
    qlen = br_i15_size_u16(q);
    uint16_t *iq = tmp + plen + qlen + 4;

    // needs to swap?
    if (br_i15_sub(p, q, 0) == 1) {
        bufswap(p, q, (1 + plen) * sizeof *p);
        bufswap(sk->p, sk->q, sk->plen);
        bufswap(sk->dp, sk->dq, sk->dplen);
    }

    // calc iq
    br_i15_zero(iq, p[0]);
    iq[1] = 1;
    br_i15_moddiv(iq, q, p, br_i15_ninv15(p[1]), iq + 1 + plen);
    sk->iq = &buffer[sk->dplen + sk->dqlen];
    sk->iqlen = sk->plen;
    br_i15_encode(sk->iq, sk->iqlen, iq);

    printf("bitlen %d\n", sk->n_bitlen);
    printf("p  [%d] %02x %02x %02x %02x .. %02x\n", sk->plen, sk->p[0], sk->p[1], sk->p[2], sk->p[3], sk->p[sk->plen - 1]);
    printf("q  [%d] %02x %02x %02x %02x .. %02x\n", sk->qlen, sk->q[0], sk->q[1], sk->q[2], sk->q[3], sk->q[sk->qlen - 1]);
    printf("dp [%d] %02x %02x %02x %02x .. %02x\n", sk->dplen, sk->dp[0], sk->dp[1], sk->dp[2], sk->dp[3], sk->dp[sk->dplen - 1]);
    printf("dq [%d] %02x %02x %02x %02x .. %02x\n", sk->dqlen, sk->dq[0], sk->dq[1], sk->dq[2], sk->dq[3], sk->dq[sk->dqlen - 1]);
    printf("iq [%d] %02x %02x %02x %02x .. %02x\n", sk->iqlen, sk->iq[0], sk->iq[1], sk->iq[2], sk->iq[3], sk->iq[sk->iqlen - 1]);

    return true;
}
