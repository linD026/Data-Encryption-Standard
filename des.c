#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "des.h"

#define pr_err(fmt, ...)                       \
    do {                                       \
        printf("[ERROR] " fmt, ##__VA_ARGS__); \
        exit(1);                               \
    } while (0)

#define pr_text(output)                        \
    do {                                       \
        printf("[TEXT]\n");                    \
        printf("\"%s\"\n", output);            \
    } while (0)

#define get_uint32(p)                      \
    ({                                     \
        struct {                           \
            uint32_t x;                    \
        } *__p_p_s = (typeof(__p_p_s))(p); \
        __p_p_s->x;                        \
    })

#define put_uint32(val, p)                 \
    ({                                     \
        struct {                           \
            uint32_t x;                    \
        } *__p_p_s = (typeof(__p_p_s))(p); \
        __p_p_s->x = val;                  \
    })

struct des_struct {
    uint8_t *input;
    uint8_t *output;
    size_t size;
    size_t ceil_size;
    uint32_t expkey[DES_EXPKEY_WORDS];
    uint64_t key[8];
};

static struct des_struct des_ctx = {
    .key = { 145345234, 345345357, 6975670340, 90256753452}
};

static inline void print_int(uint8_t *p, size_t size)
{
    uint64_t *__p = (uint64_t *)p;
    printf("[HEX]\n\"");
    do {
        printf("%016lx ", *__p);
    } while (__p += 1, size -= 8, size > 0);
    printf("\"\n");
}

void des_encrypt(uint32_t *key, uint8_t *dst, uint8_t *src)
{
    uint32_t L, R, A, B;
    int i;

    L = get_uint32(src);
    R = get_uint32(src + 4);

    IP(L, R, A);
    for (i = 0; i < 8; i++) {
        ROUND(L, R, A, B, key, 2);
        ROUND(R, L, A, B, key, 2);
    }
    FP(R, L, A);

    put_uint32(R, dst);
    put_uint32(L, dst + 4);
}

void des_decrypt(uint32_t *key, uint8_t *dst, uint8_t *src)
{
    uint32_t L, R, A, B;
    int i;
    key = key + 32 - 2;

    L = get_uint32(src);
    R = get_uint32(src + 4);

    IP(L, R, A);
    for (i = 0; i < 8; i++) {
        ROUND(L, R, A, B, key, -2);
        ROUND(R, L, A, B, key, -2);
    }
    FP(R, L, A);

    put_uint32(R, dst);
    put_uint32(L, dst + 4);
}

static unsigned long des_ekey(uint32_t *pe, const uint8_t *k)
{
	/* K&R: long is at least 32 bits */
	unsigned long a, b, c, d, w;
	const uint32_t *pt = pc2;

	d = k[4]; d &= 0x0e; d <<= 4; d |= k[0] & 0x1e; d = pc1[d];
	c = k[5]; c &= 0x0e; c <<= 4; c |= k[1] & 0x1e; c = pc1[c];
	b = k[6]; b &= 0x0e; b <<= 4; b |= k[2] & 0x1e; b = pc1[b];
	a = k[7]; a &= 0x0e; a <<= 4; a |= k[3] & 0x1e; a = pc1[a];

	pe[15 * 2 + 0] = DES_PC2(a, b, c, d); d = rs[d];
	pe[14 * 2 + 0] = DES_PC2(d, a, b, c); c = rs[c]; b = rs[b];
	pe[13 * 2 + 0] = DES_PC2(b, c, d, a); a = rs[a]; d = rs[d];
	pe[12 * 2 + 0] = DES_PC2(d, a, b, c); c = rs[c]; b = rs[b];
	pe[11 * 2 + 0] = DES_PC2(b, c, d, a); a = rs[a]; d = rs[d];
	pe[10 * 2 + 0] = DES_PC2(d, a, b, c); c = rs[c]; b = rs[b];
	pe[ 9 * 2 + 0] = DES_PC2(b, c, d, a); a = rs[a]; d = rs[d];
	pe[ 8 * 2 + 0] = DES_PC2(d, a, b, c); c = rs[c];
	pe[ 7 * 2 + 0] = DES_PC2(c, d, a, b); b = rs[b]; a = rs[a];
	pe[ 6 * 2 + 0] = DES_PC2(a, b, c, d); d = rs[d]; c = rs[c];
	pe[ 5 * 2 + 0] = DES_PC2(c, d, a, b); b = rs[b]; a = rs[a];
	pe[ 4 * 2 + 0] = DES_PC2(a, b, c, d); d = rs[d]; c = rs[c];
	pe[ 3 * 2 + 0] = DES_PC2(c, d, a, b); b = rs[b]; a = rs[a];
	pe[ 2 * 2 + 0] = DES_PC2(a, b, c, d); d = rs[d]; c = rs[c];
	pe[ 1 * 2 + 0] = DES_PC2(c, d, a, b); b = rs[b];
	pe[ 0 * 2 + 0] = DES_PC2(b, c, d, a);

	/* Check if first half is weak */
	w  = (a ^ c) | (b ^ d) | (rs[a] ^ c) | (b ^ rs[d]);

	/* Skip to next table set */
	pt += 512;

	d = k[0]; d &= 0xe0; d >>= 4; d |= k[4] & 0xf0; d = pc1[d + 1];
	c = k[1]; c &= 0xe0; c >>= 4; c |= k[5] & 0xf0; c = pc1[c + 1];
	b = k[2]; b &= 0xe0; b >>= 4; b |= k[6] & 0xf0; b = pc1[b + 1];
	a = k[3]; a &= 0xe0; a >>= 4; a |= k[7] & 0xf0; a = pc1[a + 1];

	/* Check if second half is weak */
	w |= (a ^ c) | (b ^ d) | (rs[a] ^ c) | (b ^ rs[d]);

	pe[15 * 2 + 1] = DES_PC2(a, b, c, d); d = rs[d];
	pe[14 * 2 + 1] = DES_PC2(d, a, b, c); c = rs[c]; b = rs[b];
	pe[13 * 2 + 1] = DES_PC2(b, c, d, a); a = rs[a]; d = rs[d];
	pe[12 * 2 + 1] = DES_PC2(d, a, b, c); c = rs[c]; b = rs[b];
	pe[11 * 2 + 1] = DES_PC2(b, c, d, a); a = rs[a]; d = rs[d];
	pe[10 * 2 + 1] = DES_PC2(d, a, b, c); c = rs[c]; b = rs[b];
	pe[ 9 * 2 + 1] = DES_PC2(b, c, d, a); a = rs[a]; d = rs[d];
	pe[ 8 * 2 + 1] = DES_PC2(d, a, b, c); c = rs[c];
	pe[ 7 * 2 + 1] = DES_PC2(c, d, a, b); b = rs[b]; a = rs[a];
	pe[ 6 * 2 + 1] = DES_PC2(a, b, c, d); d = rs[d]; c = rs[c];
	pe[ 5 * 2 + 1] = DES_PC2(c, d, a, b); b = rs[b]; a = rs[a];
	pe[ 4 * 2 + 1] = DES_PC2(a, b, c, d); d = rs[d]; c = rs[c];
	pe[ 3 * 2 + 1] = DES_PC2(c, d, a, b); b = rs[b]; a = rs[a];
	pe[ 2 * 2 + 1] = DES_PC2(a, b, c, d); d = rs[d]; c = rs[c];
	pe[ 1 * 2 + 1] = DES_PC2(c, d, a, b); b = rs[b];
	pe[ 0 * 2 + 1] = DES_PC2(b, c, d, a);

	/* Fixup: 2413 5768 -> 1357 2468 */
	for (d = 0; d < 16; ++d) {
		a = pe[2 * d];
		b = pe[2 * d + 1];
		c = a ^ b;
		c &= 0xffff0000;
		a ^= c;
		b ^= c;
		ROL(b, 18);
		pe[2 * d] = a;
		pe[2 * d + 1] = b;
	}

	/* Zero if weak key */
	return w;
}

static inline void do_des_encrypt(void)
{
    uint8_t *src_p = des_ctx.input, *dst_p = des_ctx.output;
    size_t size = des_ctx.ceil_size;

    do {
        des_encrypt((uint32_t *)des_ctx.expkey,
                (uint8_t *)dst_p, (uint8_t *)src_p);
    } while (dst_p += 8, src_p += 8, size -= 8, size > 0);
    printf("Encrypt text:\n\n");
    print_int(des_ctx.output, des_ctx.ceil_size);
    pr_text(des_ctx.output);
}

static inline void do_des_decrypt(void)
{
    uint8_t *src_p = des_ctx.input, *dst_p = des_ctx.output;
    size_t size = des_ctx.ceil_size;

    do {
        des_decrypt((uint32_t *)des_ctx.expkey,
                (uint8_t *)dst_p, (uint8_t *)src_p);
    } while (dst_p += 8, src_p += 8, size -= 8, size > 0);
    printf("Decrypt text:\n\n");
    print_int(des_ctx.output, des_ctx.ceil_size);
    pr_text(des_ctx.output);
}

static inline void des_setkey(void)
{
	des_ekey((uint32_t *)des_ctx.expkey, (uint8_t *)des_ctx.key);
}

static inline void __encrypt_get_text(void)
{
   memcpy(des_ctx.input, optarg, des_ctx.size);
}

static inline void __dencrypt_get_text(void)
{
    char *next_p, *src_p = optarg;
    uint64_t src, *dst_p = (uint64_t *)des_ctx.input;
    size_t i = des_ctx.ceil_size;

    for (;i > 0; i -= 8, src_p = next_p) {
        src = strtoull(src_p, &next_p, 16);
        *dst_p = src;
        dst_p += 1;
        next_p += 1;
    }
}

static void get_text(int opt)
{
    if (!optarg)
        pr_err("Doesn't have an input text\n");

    /* one charater is 1 byte (8 bits), one block is 64 bits (8 bytes)
     * so if the size is not n*8 bytes, add it to be n*8 size.
     *
     * if the opt is d, which mean decryption, the input will be:
     * "ffffffffffffffff " in a block (the number is hex format)
     * so at this we must deal with 17 bytes as a unit (8 bytes).
     */
    des_ctx.ceil_size = des_ctx.size = strlen(optarg);
    if (des_ctx.ceil_size == 0)
            pr_err("NON INPUT\n");
    else if (opt == 'd') {
        if (des_ctx.ceil_size % 17)
            pr_err("decrytion input error (%zu bytes)\n"
                    "Decrytion format: \"[16 charater of hex][one space] ...\""
                    "\n Your input is:\n%s\n", des_ctx.ceil_size, optarg);
        des_ctx.ceil_size /= 17;
        des_ctx.ceil_size *= 8;
    }
    else if (des_ctx.ceil_size & 7) {
        des_ctx.ceil_size &= ~7;
        des_ctx.ceil_size += 8;
    }

    des_ctx.input = (uint8_t *)malloc(des_ctx.ceil_size);
    if (!des_ctx.input)
        pr_err("malloc failed (input)\n");
    memset(des_ctx.input, 0, des_ctx.ceil_size);
    
    // for the end print need one btye more space to store '\0'
    des_ctx.output = (uint8_t *)malloc(des_ctx.ceil_size + 1);
    if (!des_ctx.output)
        pr_err("malloc failed (output)\n");
    memset(des_ctx.output, 0, des_ctx.ceil_size + 1);

    if (opt == 'd')
        __dencrypt_get_text();
    else
        __encrypt_get_text();

    printf("original text (ceil size %zu bytes, size %zu bytes):\n\n",
            des_ctx.ceil_size, des_ctx.size);
    print_int(des_ctx.input, des_ctx.ceil_size);
    printf("\n");
}

static void test_en_de(void)
{
    uint8_t *orig_src_p;
    uint8_t *encypted = (uint8_t *)malloc(des_ctx.ceil_size);
    if (!encypted)
        pr_err("malloc failed (encypted)");
    memset(encypted, 0, des_ctx.ceil_size);

    do_des_encrypt();
    
    orig_src_p = des_ctx.input;
    des_ctx.input = des_ctx.output;
    des_ctx.output = encypted;
    printf("\n");
    
    do_des_decrypt();

    if (strncmp((char *)orig_src_p, (char *)des_ctx.output, 64) == 0)
        printf("\nPassed\n");

    des_ctx.output = orig_src_p;
    free(encypted);
}

int main(int argc, char *argv[])
{
    int opt;

    printf("---\n");
    des_setkey();
    while ((opt = getopt(argc, argv, "e:d:a:"))) {
        get_text(opt);
        switch (opt) {
        case 'e':
            do_des_encrypt();
            goto done;
        case 'd':
            do_des_decrypt();
            goto done;
        case 'a':
            test_en_de();
            goto done; 
        default:
            printf("Usage: %s [-e encrypt] [-d decrypt]"
                   " [-a test encrypt decrypt] text\n", argv[0]);
            pr_err("Unkown option\n");
        }
    }

done:
    free(des_ctx.input);
    free(des_ctx.output);

    printf("---\n");
    return 0;
}
