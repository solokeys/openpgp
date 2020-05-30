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
        if (u == 1) bw = b & 0xffffU;
        if (u == 2) bw = b >> 16;

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
        if (u == 1) bw = b & 0xffffU;
        if (u == 2) bw = b >> 16;

        naw = aw + bw + cc;
        cc = naw >> 15;
        a[u] = MUX(ctl, naw & 0x7FFF, aw);
    }
    return cc;
}

uint32_t br_i15_size_int_u16(uint16_t *a) {
    return (a[0] + 31) >> 4;
}

uint32_t br_i15_size_u16(uint16_t *a) {
    return br_i15_size_int_u16(a) + 1; // plus length u16
}

// from rsa_i15_keygen.c
static uint32_t
invert_pubexp(uint16_t *d, const uint16_t *m, uint32_t e, uint16_t *t)
{
    uint16_t *f;
    uint32_t r;

    f = t;
    t += 1 + ((m[0] + 15) >> 4);

    /*
     * Compute d = 1/e mod m. Since p = 3 mod 4, m is odd.
     */
    br_i15_zero(d, m[0]);
    d[1] = 1;
    br_i15_zero(f, m[0]);
    f[1] = e & 0x7FFF;
    f[2] = (e >> 15) & 0x7FFF;
    f[3] = e >> 30;
    r = br_i15_moddiv(d, f, m, br_i15_ninv15(m[1]), t);

    /*
     * We really want d = 1/e mod p-1, with p = 2m. By the CRT,
     * the result is either the d we got, or d + m.
     *
     * Let's write e*d = 1 + k*m, for some integer k. Integers e
     * and m are odd. If d is odd, then e*d is odd, which implies
     * that k must be even; in that case, e*d = 1 + (k/2)*2m, and
     * thus d is already fine. Conversely, if d is even, then k
     * is odd, and we must add m to d in order to get the correct
     * result.
     */
    br_i15_add(d, m, (uint32_t)(1 - (d[1] & 1)));

    return r;
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

bool br_rsa_deduce_crt(uint8_t *buffer, br_rsa_private_key *sk, uint8_t *exp) {

    uint32_t exp32 = br_dec32be(exp);

    // size variants:
    // 1. p or q and 4 bigints
    // 2. p and q and 4 bigints
    uint16_t tmp[2048]; // TODO: add calc here
    memset(tmp, 0, sizeof(tmp));

    // get p
    uint16_t *p = tmp;
    br_i15_decode(p, sk->p, sk->plen);
    size_t plen = br_i15_size_u16(p);
    br_i15_rshift(p, 1);
    uint16_t *dp = tmp + plen;

    // calc dp
    if (!invert_pubexp(dp, p, exp32, dp + 1 + plen))
        return false;
    sk->dp = &buffer[0];
    sk->dplen = sk->plen;
    br_i15_encode(sk->dp, sk->dplen, dp);

    //br_i15_print_int("p", p);
    //br_i15_print_int("dp", dp);

    // get q
    uint16_t *q = tmp;
    br_i15_decode(q, sk->q, sk->qlen);
    size_t qlen = br_i15_size_u16(q);
    br_i15_rshift(q, 1);
    uint16_t *dq = tmp + qlen;

    // calc dq
    if (!invert_pubexp(dq, q, exp32, dq + 1 + qlen))
        return false;
    sk->dq = &buffer[sk->dplen];
    sk->dqlen = sk->plen;
    br_i15_encode(sk->dq, sk->dqlen, dq);

    //printf("--plen %d qlen %d dplen %d dqlen %d\n", plen, qlen, sk->dplen, sk->dqlen);
    //br_i15_print_int("q", q);
    //br_i15_print_int("dq", dq);

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

    // make equal size of p and q
    q[0] = p[0];
    if (plen > qlen) {
        q[qlen] = 0;
    }

    // calc iq
    br_i15_zero(iq, p[0]);
    iq[1] = 1;
    br_i15_moddiv(iq, q, p, br_i15_ninv15(p[1]), iq + 1 + plen);
    sk->iq = &buffer[sk->dplen + sk->dqlen];
    sk->iqlen = sk->plen;
    br_i15_encode(sk->iq, sk->iqlen, iq);

    printf("--plen %d qlen %d iqlen %d\n", plen, qlen, sk->iqlen);
    //br_i15_print_int("q", q);
    //br_i15_print_int("iq", iq);

    printf("bitlen %d\n", sk->n_bitlen);
    printf("p  %02x %02x %02x %02x\n", sk->p[0], sk->p[1], sk->p[2], sk->p[3]);
    printf("q  %02x %02x %02x %02x\n", sk->q[0], sk->q[1], sk->q[2], sk->q[3]);
    printf("dp %02x %02x %02x %02x\n", sk->dp[0], sk->dp[1], sk->dp[2], sk->dp[3]);
    printf("dq %02x %02x %02x %02x\n", sk->dq[0], sk->dq[1], sk->dq[2], sk->dq[3]);
    printf("iq %02x %02x %02x %02x\n", sk->iq[0], sk->iq[1], sk->iq[2], sk->iq[3]);

    return true;
}
