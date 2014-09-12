//
//  main.c
//  sha1
//
//  Created by Alex Ushakov on 09/09/14.
//  Copyright (c) 2014 Alex Komnin. All rights reserved.
//

#include <stdio.h>
#include <string.h>

#define F_00_19(M, L, K)    (((M) & (L)) | (~(M) & (K)))
#define F_20_39(M, L, K)    ((M) ^ (L) ^ (K))
#define F_40_59(M, L, K)    (((M) & (L)) | ((M) & (K)) | ((L) & (K)))
#define F_60_79(M, L, K)    F_20_39((M), (L), (K))

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
    
    for (int i = 0; i < 20; ++i)
    {
        uint32_t tmp = _rotl(a, 5) + F_00_19(b, c, d) + e + K_00_19 + W[i];
        e = d; d = c; c = _rotl(b, 30); b = a;
        a = tmp;
    }
    
    for (int i = 20; i < 40; ++i)
    {
        uint32_t tmp = _rotl(a, 5) + F_20_39(b, c, d) + e + K_20_39 + W[i];
        e = d; d = c; c = _rotl(b, 30); b = a;
        a = tmp;
    }
    
    for (int i = 40; i < 60; ++i)
    {
        uint32_t tmp = _rotl(a, 5) + F_40_59(b, c, d) + e + K_40_59 + W[i];
        e = d; d = c; c = _rotl(b, 30); b = a;
        a = tmp;
    }
    
    for (int i = 60; i < 80; ++i)
    {
        uint32_t tmp = _rotl(a, 5) + F_60_79(b, c, d) + e + K_60_79 + W[i];
        e = d; d = c; c = _rotl(b, 30); b = a;
        a = tmp;
    }
    
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

