#!/bin/bash
export PATH="/usr/bin:$PATH"

cat > /tmp/sha256.c << 'CSRC'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static const uint32_t H0[8] = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
};

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define SIG0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define SIG1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define sig0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define sig1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

typedef struct {
    uint32_t h[8];
    uint8_t  buf[64];
    uint64_t total_bits;
    uint32_t buf_len;
} sha256_ctx;

static void sha256_compress(sha256_ctx *ctx, const uint8_t block[64]) {
    uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|
               ((uint32_t)block[i*4+2]<<8)|(uint32_t)block[i*4+3];
    for (i = 16; i < 64; i++)
        w[i] = sig1(w[i-2]) + w[i-7] + sig0(w[i-15]) + w[i-16];
    a=ctx->h[0]; b=ctx->h[1]; c=ctx->h[2]; d=ctx->h[3];
    e=ctx->h[4]; f=ctx->h[5]; g=ctx->h[6]; h=ctx->h[7];
    for (i = 0; i < 64; i++) {
        t1 = h + SIG1(e) + CH(e,f,g) + K[i] + w[i];
        t2 = SIG0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1;
        d=c; c=b; b=a; a=t1+t2;
    }
    ctx->h[0]+=a; ctx->h[1]+=b; ctx->h[2]+=c; ctx->h[3]+=d;
    ctx->h[4]+=e; ctx->h[5]+=f; ctx->h[6]+=g; ctx->h[7]+=h;
}

static void sha256_init(sha256_ctx *ctx) {
    memcpy(ctx->h, H0, sizeof(H0));
    ctx->total_bits = 0;
    ctx->buf_len = 0;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->total_bits += (uint64_t)len * 8;
    while (len > 0) {
        uint32_t space = 64 - ctx->buf_len;
        uint32_t take = (len < space) ? (uint32_t)len : space;
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        data += take;
        len  -= take;
        if (ctx->buf_len == 64) {
            sha256_compress(ctx, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t digest[32]) {
    uint64_t bits = ctx->total_bits;
    uint8_t pad[72];
    uint32_t pad_len, i;
    pad[0] = 0x80;
    pad_len = (ctx->buf_len < 56) ? (56 - ctx->buf_len) : (120 - ctx->buf_len);
    memset(pad + 1, 0, pad_len - 1);
    sha256_update(ctx, pad, pad_len);
    uint8_t len_bytes[8];
    for (i = 0; i < 8; i++)
        len_bytes[i] = (uint8_t)(bits >> (56 - i*8));
    sha256_update(ctx, len_bytes, 8);
    for (i = 0; i < 8; i++) {
        digest[i*4]   = (ctx->h[i]>>24)&0xff;
        digest[i*4+1] = (ctx->h[i]>>16)&0xff;
        digest[i*4+2] = (ctx->h[i]>>8)&0xff;
        digest[i*4+3] =  ctx->h[i]&0xff;
    }
}

int main(int argc, char *argv[]) {
    sha256_ctx ctx;
    uint8_t buf[4096], digest[32];
    FILE *f;
    size_t n;
    int i;
    if (argc < 2) { fprintf(stderr, "usage: sha256 <file|->\n"); return 1; }
    f = (strcmp(argv[1], "-") == 0) ? stdin : fopen(argv[1], "rb");
    if (!f) { perror("open"); return 1; }
    sha256_init(&ctx);
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        sha256_update(&ctx, buf, n);
    if (f != stdin) fclose(f);
    sha256_final(&ctx, digest);
    for (i = 0; i < 32; i++) printf("%02x", digest[i]);
    printf("\n");
    return 0;
}
CSRC

gcc -O2 -Wall -o /app/sha256 /tmp/sha256.c
rm -f /tmp/sha256.c