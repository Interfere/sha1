// Created by Alex Komnin on 09/09/14.
// Update by Nicolas Reynaud on 02/26/15.
//
// Copyright (c) 2014 Alex Komnin. All rights reserved.
//
#include <stdio.h>
#include <string.h>

#ifdef WIN32
    typedef __int32 int32_t;
    typedef unsigned __int64 uint64_t;
    typedef unsigned __int32 uint32_t;
    typedef unsigned __int16 uint16_t;
#endif

struct SHA_ctx {
    uint32_t A, B, C, D, E;
};



#define F_60_79 F_20_39
#define SHA1_ONE_ITER(a, b, c, d, e, K, F, X) \
(e) = _rotl((a), 5) + F((b), (c), (d)) + (e) + (K) + (X),(b) = _rotl((b), 30)
#define SHA1_UPDATE_BUF(W, N) \
(W)[(N)%16] = _rotl((W)[((N)+13)%16] ^ (W)[((N)+8)%16] ^ (W)[((N)+2)%16] ^ (W)[(N)%16], 1)
#define SHA1_BLOCK(a, b, c, d, e, K, F, W, N) \
SHA1_ONE_ITER(a, b, c, d, e, K, F, SHA1_UPDATE_BUF(W, (N)));\
SHA1_ONE_ITER(e, a, b, c, d, K, F, SHA1_UPDATE_BUF(W, (N)+1));\
SHA1_ONE_ITER(d, e, a, b, c, K, F, SHA1_UPDATE_BUF(W, (N)+2));\
SHA1_ONE_ITER(c, d, e, a, b, K, F, SHA1_UPDATE_BUF(W, (N)+3));\
SHA1_ONE_ITER(b, c, d, e, a, K, F, SHA1_UPDATE_BUF(W, (N)+4));\
SHA1_ONE_ITER(a, b, c, d, e, K, F, SHA1_UPDATE_BUF(W, (N)+5));\
SHA1_ONE_ITER(e, a, b, c, d, K, F, SHA1_UPDATE_BUF(W, (N)+6));\
SHA1_ONE_ITER(d, e, a, b, c, K, F, SHA1_UPDATE_BUF(W, (N)+7));\
SHA1_ONE_ITER(c, d, e, a, b, K, F, SHA1_UPDATE_BUF(W, (N)+8));\
SHA1_ONE_ITER(b, c, d, e, a, K, F, SHA1_UPDATE_BUF(W, (N)+9));\
SHA1_ONE_ITER(a, b, c, d, e, K, F, SHA1_UPDATE_BUF(W, (N)+10));\
SHA1_ONE_ITER(e, a, b, c, d, K, F, SHA1_UPDATE_BUF(W, (N)+11));\
SHA1_ONE_ITER(d, e, a, b, c, K, F, SHA1_UPDATE_BUF(W, (N)+12));\
SHA1_ONE_ITER(c, d, e, a, b, K, F, SHA1_UPDATE_BUF(W, (N)+13));\
SHA1_ONE_ITER(b, c, d, e, a, K, F, SHA1_UPDATE_BUF(W, (N)+14));\
SHA1_ONE_ITER(a, b, c, d, e, K, F, SHA1_UPDATE_BUF(W, (N)+15));\
SHA1_ONE_ITER(e, a, b, c, d, K, F, SHA1_UPDATE_BUF(W, (N)));\
SHA1_ONE_ITER(d, e, a, b, c, K, F, SHA1_UPDATE_BUF(W, (N)+1));\
SHA1_ONE_ITER(c, d, e, a, b, K, F, SHA1_UPDATE_BUF(W, (N)+2));\
SHA1_ONE_ITER(b, c, d, e, a, K, F, SHA1_UPDATE_BUF(W, (N)+3))

static inline uint32_t F_00_19(uint32_t x, uint32_t y, uint32_t u) {
    return ((x & y) | (~x & u));
}

static inline uint32_t F_20_39(uint32_t x, uint32_t y, uint32_t u) {
    return x ^ y ^ u;
}

static inline uint32_t F_40_59(uint32_t x, uint32_t y, uint32_t u) {
    return ((x & y) | (x & u) | (y & u));
}

static inline uint16_t bswap_16(uint16_t x) {
    return (x >> 8) | (x << 8);
}

static inline uint32_t bswap_32(uint32_t x) {
    return (bswap_16(x & 0xFFFF) << 16) | bswap_16(x >> 16);
}

static inline uint64_t bswap_64(uint64_t x) {
    return (((uint64_t)bswap_32(x & 0xFFFFFFFF)) << 32) | bswap_32(x >> 32);
}

static inline uint32_t _rotl(uint32_t x, int shift) {
    return (x << shift) | (x >> (32 - shift));
}

static void SHA1_calc(struct SHA_ctx *ctx, uint32_t M[16]) {
    int t;

    static const uint32_t K_00_19 = 0x5A827999;
    static const uint32_t K_20_39 = 0x6ED9EBA1;
    static const uint32_t K_40_59 = 0x8F1BBCDC;
    static const uint32_t K_60_79 = 0xCA62C1D6;
	
    uint32_t a = ctx->A, b = ctx->B, c = ctx->C, d = ctx->D, e = ctx->E;
    uint32_t W[80];
	
    W[0] = bswap_32(M[0]);
    SHA1_ONE_ITER(a, b, c, d, e, K_00_19, F_00_19, W[0]);
	
    W[1] = bswap_32(M[1]);
    SHA1_ONE_ITER(e, a, b, c, d, K_00_19, F_00_19, W[1]);
	
    W[2] = bswap_32(M[2]);
    SHA1_ONE_ITER(d, e, a, b, c, K_00_19, F_00_19, W[2]);
	
    W[3] = bswap_32(M[3]);
    SHA1_ONE_ITER(c, d, e, a, b, K_00_19, F_00_19, W[3]);
	
    W[4] = bswap_32(M[4]);
    SHA1_ONE_ITER(b, c, d, e, a, K_00_19, F_00_19, W[4]);
	
    W[5] = bswap_32(M[5]);
    SHA1_ONE_ITER(a, b, c, d, e, K_00_19, F_00_19, W[5]);
	
    W[6] = bswap_32(M[6]);
    SHA1_ONE_ITER(e, a, b, c, d, K_00_19, F_00_19, W[6]);
	
    W[7] = bswap_32(M[7]);
    SHA1_ONE_ITER(d, e, a, b, c, K_00_19, F_00_19, W[7]);
	
    W[8] = bswap_32(M[8]);
    SHA1_ONE_ITER(c, d, e, a, b, K_00_19, F_00_19, W[8]);
	
    W[9] = bswap_32(M[9]);
    SHA1_ONE_ITER(b, c, d, e, a, K_00_19, F_00_19, W[9]);
	
    W[10] = bswap_32(M[10]);
    SHA1_ONE_ITER(a, b, c, d, e, K_00_19, F_00_19, W[10]);
	
    W[11] = bswap_32(M[11]);
    SHA1_ONE_ITER(e, a, b, c, d, K_00_19, F_00_19, W[11]);
	
    W[12] = bswap_32(M[12]);
    SHA1_ONE_ITER(d, e, a, b, c, K_00_19, F_00_19, W[12]);
	
    W[13] = bswap_32(M[13]);
    SHA1_ONE_ITER(c, d, e, a, b, K_00_19, F_00_19, W[13]);
	
    W[14] = bswap_32(M[14]);
    SHA1_ONE_ITER(b, c, d, e, a, K_00_19, F_00_19, W[14]);
	
    W[15] = bswap_32(M[15]);
    SHA1_ONE_ITER(a, b, c, d, e, K_00_19, F_00_19, W[15]);

    for (t = 16; t < 80; ++t) {
        W[t] = _rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }

    SHA1_ONE_ITER(e, a, b, c, d, K_00_19, F_00_19, SHA1_UPDATE_BUF(W, 0));
    SHA1_ONE_ITER(d, e, a, b, c, K_00_19, F_00_19, SHA1_UPDATE_BUF(W, 1));
    SHA1_ONE_ITER(c, d, e, a, b, K_00_19, F_00_19, SHA1_UPDATE_BUF(W, 2));
    SHA1_ONE_ITER(b, c, d, e, a, K_00_19, F_00_19, SHA1_UPDATE_BUF(W, 3));
    SHA1_BLOCK(a, b, c, d, e, K_20_39, F_20_39, W, 4);
    SHA1_BLOCK(a, b, c, d, e, K_40_59, F_40_59, W, 8);
    SHA1_BLOCK(a, b, c, d, e, K_60_79, F_60_79, W, 12);
    ctx->A += a;
    ctx->B += b;
    ctx->C += c;
    ctx->D += d;
    ctx->E += e;
}

int SHA1(const char* src, size_t nlen, unsigned char* md) {
    struct SHA_ctx ctx = {
    .A = 0x67452301,
    .B = 0xEFCDAB89,
    .C = 0x98BADCFE,
    .D = 0x10325476,
    .E = 0xC3D2E1F0
    };

    uint64_t size = nlen * 8;

    while (nlen >= 64) {
        uint32_t* m = (uint32_t *)src;
        SHA1_calc(&ctx, m);
        nlen -= 64;
        src += 64;
    }

    char M[64];
    memcpy(M, src, nlen);
    M[nlen] = 0x80;
    memset(M + nlen + 1, 0, sizeof(M) - nlen - 1);
    if(nlen >= 56) {
        SHA1_calc(&ctx, (uint32_t *)M);
        memset(M, 0, 56);
    }
    *(uint64_t *)(M + 56) = bswap_64(size);
    SHA1_calc(&ctx, (uint32_t *)M);
    uint32_t* inMd = (uint32_t *)md;
    inMd[0] = bswap_32(ctx.A);
    inMd[1] = bswap_32(ctx.B);
    inMd[2] = bswap_32(ctx.C);
    inMd[3] = bswap_32(ctx.D);
    inMd[4] = bswap_32(ctx.E);

    return 0;
}

void usage(const char *argv) {
    printf("Usage: %s <string>\n"
    "Print SHA-1 hash of the string.\n", argv);
}

int main(int argc, const char * argv[]) {

    if(argc < 2) {
        usage(argv[0]);
        return(-1);
    }

    int i;
    unsigned char md[20];

    SHA1(argv[1], strlen(argv[1]), md);

    printf("SHA 1 : ");
    for ( i = 0; i < 20; i++) {
        printf("%02x", md[i]);
    }
    printf("\n");

    return(0);
}
