//
//  main.c
//  sha1
//
//  Created by Alex Ushakov on 09/09/14.
//  Copyright (c) 2014 Alex Komnin. All rights reserved.
//

#include <stdio.h>
#include <string.h>

#define F_60_79(M, L, K)    F_20_39((M), (L), (K))

#define SHA1_ONE_ITER(a, b, c, d, e, K, F, X) \
(e) = _rotl((a), 5) + F((b), (c), (d)) + (e) + (K) + (X),(b) = _rotl((b), 30)

static inline uint32_t F_00_19(uint32_t x, uint32_t y, uint32_t u)
{
    return ((x & y) | (~x & u));
}

static inline uint32_t F_20_39(uint32_t x, uint32_t y, uint32_t u)
{
    return x ^ y ^ u;
}

static inline uint32_t F_40_59(uint32_t x, uint32_t y, uint32_t u)
{
    return ((x & y) | (x & u) | (y & u));
}

static inline uint16_t bswap_16(uint16_t x)
{
    return (x >> 8) | (x << 8);
}

static inline uint32_t bswap_32(uint32_t x)
{
    return (bswap_16(x & 0xFFFF) << 16) | bswap_16(x >> 16);
}

static inline uint64_t bswap_64(uint64_t x)
{
    return (((uint64_t)bswap_32(x & 0xFFFFFFFF)) << 32) | bswap_32(x >> 32);
}

static inline uint32_t _rotl(uint32_t x, int shift)
{
    return (x << shift) | (x >> (32 - shift));
}

struct SHA_ctx
{
    uint32_t A, B, C, D, E;
};

static void SHA1_calc(struct SHA_ctx *ctx, uint32_t M[16])
{
    static const uint32_t K_00_19 = 0x5A827999;
    static const uint32_t K_20_39 = 0x6ED9EBA1;
    static const uint32_t K_40_59 = 0x8F1BBCDC;
    static const uint32_t K_60_79 = 0xCA62C1D6;
    uint32_t a = ctx->A, b = ctx->B, c = ctx->C, d = ctx->D, e = ctx->E;
    uint32_t W[80];
    
    for(int t = 0; t < 16; ++t)
    {
        W[t] = bswap_32(M[t]);
    }
    
    for (int t = 16; t < 80; ++t)
    {
        W[t] = _rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }
    
    SHA1_ONE_ITER(a, b, c, d, e, K_00_19, F_00_19, W[0]);
    SHA1_ONE_ITER(e, a, b, c, d, K_00_19, F_00_19, W[1]);
    SHA1_ONE_ITER(d, e, a, b, c, K_00_19, F_00_19, W[2]);
    SHA1_ONE_ITER(c, d, e, a, b, K_00_19, F_00_19, W[3]);
    SHA1_ONE_ITER(b, c, d, e, a, K_00_19, F_00_19, W[4]);
    SHA1_ONE_ITER(a, b, c, d, e, K_00_19, F_00_19, W[5]);
    SHA1_ONE_ITER(e, a, b, c, d, K_00_19, F_00_19, W[6]);
    SHA1_ONE_ITER(d, e, a, b, c, K_00_19, F_00_19, W[7]);
    SHA1_ONE_ITER(c, d, e, a, b, K_00_19, F_00_19, W[8]);
    SHA1_ONE_ITER(b, c, d, e, a, K_00_19, F_00_19, W[9]);
    SHA1_ONE_ITER(a, b, c, d, e, K_00_19, F_00_19, W[10]);
    SHA1_ONE_ITER(e, a, b, c, d, K_00_19, F_00_19, W[11]);
    SHA1_ONE_ITER(d, e, a, b, c, K_00_19, F_00_19, W[12]);
    SHA1_ONE_ITER(c, d, e, a, b, K_00_19, F_00_19, W[13]);
    SHA1_ONE_ITER(b, c, d, e, a, K_00_19, F_00_19, W[14]);
    SHA1_ONE_ITER(a, b, c, d, e, K_00_19, F_00_19, W[15]);
    SHA1_ONE_ITER(e, a, b, c, d, K_00_19, F_00_19, W[16]);
    SHA1_ONE_ITER(d, e, a, b, c, K_00_19, F_00_19, W[17]);
    SHA1_ONE_ITER(c, d, e, a, b, K_00_19, F_00_19, W[18]);
    SHA1_ONE_ITER(b, c, d, e, a, K_00_19, F_00_19, W[19]);
    
    SHA1_ONE_ITER(a, b, c, d, e, K_20_39, F_20_39, W[20]);
    SHA1_ONE_ITER(e, a, b, c, d, K_20_39, F_20_39, W[21]);
    SHA1_ONE_ITER(d, e, a, b, c, K_20_39, F_20_39, W[22]);
    SHA1_ONE_ITER(c, d, e, a, b, K_20_39, F_20_39, W[23]);
    SHA1_ONE_ITER(b, c, d, e, a, K_20_39, F_20_39, W[24]);
    SHA1_ONE_ITER(a, b, c, d, e, K_20_39, F_20_39, W[25]);
    SHA1_ONE_ITER(e, a, b, c, d, K_20_39, F_20_39, W[26]);
    SHA1_ONE_ITER(d, e, a, b, c, K_20_39, F_20_39, W[27]);
    SHA1_ONE_ITER(c, d, e, a, b, K_20_39, F_20_39, W[28]);
    SHA1_ONE_ITER(b, c, d, e, a, K_20_39, F_20_39, W[29]);
    SHA1_ONE_ITER(a, b, c, d, e, K_20_39, F_20_39, W[30]);
    SHA1_ONE_ITER(e, a, b, c, d, K_20_39, F_20_39, W[31]);
    SHA1_ONE_ITER(d, e, a, b, c, K_20_39, F_20_39, W[32]);
    SHA1_ONE_ITER(c, d, e, a, b, K_20_39, F_20_39, W[33]);
    SHA1_ONE_ITER(b, c, d, e, a, K_20_39, F_20_39, W[34]);
    SHA1_ONE_ITER(a, b, c, d, e, K_20_39, F_20_39, W[35]);
    SHA1_ONE_ITER(e, a, b, c, d, K_20_39, F_20_39, W[36]);
    SHA1_ONE_ITER(d, e, a, b, c, K_20_39, F_20_39, W[37]);
    SHA1_ONE_ITER(c, d, e, a, b, K_20_39, F_20_39, W[38]);
    SHA1_ONE_ITER(b, c, d, e, a, K_20_39, F_20_39, W[39]);
    
    SHA1_ONE_ITER(a, b, c, d, e, K_40_59, F_40_59, W[40]);
    SHA1_ONE_ITER(e, a, b, c, d, K_40_59, F_40_59, W[41]);
    SHA1_ONE_ITER(d, e, a, b, c, K_40_59, F_40_59, W[42]);
    SHA1_ONE_ITER(c, d, e, a, b, K_40_59, F_40_59, W[43]);
    SHA1_ONE_ITER(b, c, d, e, a, K_40_59, F_40_59, W[44]);
    SHA1_ONE_ITER(a, b, c, d, e, K_40_59, F_40_59, W[45]);
    SHA1_ONE_ITER(e, a, b, c, d, K_40_59, F_40_59, W[46]);
    SHA1_ONE_ITER(d, e, a, b, c, K_40_59, F_40_59, W[47]);
    SHA1_ONE_ITER(c, d, e, a, b, K_40_59, F_40_59, W[48]);
    SHA1_ONE_ITER(b, c, d, e, a, K_40_59, F_40_59, W[49]);
    SHA1_ONE_ITER(a, b, c, d, e, K_40_59, F_40_59, W[50]);
    SHA1_ONE_ITER(e, a, b, c, d, K_40_59, F_40_59, W[51]);
    SHA1_ONE_ITER(d, e, a, b, c, K_40_59, F_40_59, W[52]);
    SHA1_ONE_ITER(c, d, e, a, b, K_40_59, F_40_59, W[53]);
    SHA1_ONE_ITER(b, c, d, e, a, K_40_59, F_40_59, W[54]);
    SHA1_ONE_ITER(a, b, c, d, e, K_40_59, F_40_59, W[55]);
    SHA1_ONE_ITER(e, a, b, c, d, K_40_59, F_40_59, W[56]);
    SHA1_ONE_ITER(d, e, a, b, c, K_40_59, F_40_59, W[57]);
    SHA1_ONE_ITER(c, d, e, a, b, K_40_59, F_40_59, W[58]);
    SHA1_ONE_ITER(b, c, d, e, a, K_40_59, F_40_59, W[59]);
    
    SHA1_ONE_ITER(a, b, c, d, e, K_60_79, F_60_79, W[60]);
    SHA1_ONE_ITER(e, a, b, c, d, K_60_79, F_60_79, W[61]);
    SHA1_ONE_ITER(d, e, a, b, c, K_60_79, F_60_79, W[62]);
    SHA1_ONE_ITER(c, d, e, a, b, K_60_79, F_60_79, W[63]);
    SHA1_ONE_ITER(b, c, d, e, a, K_60_79, F_60_79, W[64]);
    SHA1_ONE_ITER(a, b, c, d, e, K_60_79, F_60_79, W[65]);
    SHA1_ONE_ITER(e, a, b, c, d, K_60_79, F_60_79, W[66]);
    SHA1_ONE_ITER(d, e, a, b, c, K_60_79, F_60_79, W[67]);
    SHA1_ONE_ITER(c, d, e, a, b, K_60_79, F_60_79, W[68]);
    SHA1_ONE_ITER(b, c, d, e, a, K_60_79, F_60_79, W[69]);
    SHA1_ONE_ITER(a, b, c, d, e, K_60_79, F_60_79, W[70]);
    SHA1_ONE_ITER(e, a, b, c, d, K_60_79, F_60_79, W[71]);
    SHA1_ONE_ITER(d, e, a, b, c, K_60_79, F_60_79, W[72]);
    SHA1_ONE_ITER(c, d, e, a, b, K_60_79, F_60_79, W[73]);
    SHA1_ONE_ITER(b, c, d, e, a, K_60_79, F_60_79, W[74]);
    SHA1_ONE_ITER(a, b, c, d, e, K_60_79, F_60_79, W[75]);
    SHA1_ONE_ITER(e, a, b, c, d, K_60_79, F_60_79, W[76]);
    SHA1_ONE_ITER(d, e, a, b, c, K_60_79, F_60_79, W[77]);
    SHA1_ONE_ITER(c, d, e, a, b, K_60_79, F_60_79, W[78]);
    SHA1_ONE_ITER(b, c, d, e, a, K_60_79, F_60_79, W[79]);
    
    ctx->A += a;
    ctx->B += b;
    ctx->C += c;
    ctx->D += d;
    ctx->E += e;
}

int SHA1(const char* src, size_t nlen, unsigned char* md)
{
    struct SHA_ctx ctx = {
        .A = 0x67452301,
        .B = 0xEFCDAB89,
        .C = 0x98BADCFE,
        .D = 0x10325476,
        .E = 0xC3D2E1F0
    };
    
    uint64_t size = nlen * 8;
    while (nlen >= 64)
    {
        uint32_t* m = (uint32_t *)src;
        SHA1_calc(&ctx, m);
        nlen -= 64;
        src += 64;
    }
    
    char M[64];
    memcpy(M, src, nlen);
    M[nlen] = 0x80;
    memset(M + nlen + 1, 0, sizeof(M) - nlen - 1);
    
    if(nlen >= 56)
    {
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

void print_help()
{
    printf("Usage: sha1 <string>\n"
           "Print SHA-1 hash of the string.\n");
}

int main(int argc, const char * argv[])
{
    if(argc != 2)
    {
        print_help();
        return 0;
    }
    
    
    unsigned char md[20];
    SHA1(argv[1], strlen(argv[1]), md);
    
    printf("sha1: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
           md[0], md[1], md[2], md[3],
           md[4], md[5], md[6], md[7],
           md[8], md[9], md[10], md[11],
           md[12], md[13], md[14], md[15],
           md[16], md[17], md[18], md[19]);
    
    return 0;
}

