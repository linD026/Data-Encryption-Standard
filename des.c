#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>


#define pr_err(fmt, ...)                       \
    do {                                       \
        printf("[ERROR] " fmt, ##__VA_ARGS__); \
        exit(1);                               \
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
    uint64_t key[64];
};

static struct des_struct des_ctx = {
    .key = {0}
};

#include "des.h"

static inline void print_int(uint8_t *p, size_t size)
{
    do {
        printf("%llu ", *(uint64_t *)p);
    } while (size -= 64, size > 0);
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

static inline void do_des_encrypt(void)
{
    uint8_t *src_p = des_ctx.input, *dst_p = des_ctx.output;
    size_t size = des_ctx.ceil_size;

    do {
        des_encrypt((uint32_t *)des_ctx.key, (uint8_t *)dst_p, (uint8_t *)src_p);
    } while (dst_p += 8, src_p += 8, size -= 8, size > 0);
    printf("Encrypt text:\n");
    printf("digit: \"");
    print_int(des_ctx.output, des_ctx.ceil_size);
    printf("\"\n");
    printf("text: \"%s\"\n", des_ctx.output);
}

static inline void do_des_decrypt(void)
{
    uint8_t *src_p = des_ctx.input, *dst_p = des_ctx.output;
    size_t size = des_ctx.ceil_size;

    do {
        des_decrypt((uint32_t *)des_ctx.key, (uint8_t *)dst_p, (uint8_t *)src_p);
    } while (dst_p += 8, src_p += 8, size -= 8, size > 0);
    printf("Decrypt text:\n");
    printf("digit: \"");
    print_int(des_ctx.output, des_ctx.ceil_size);
    printf("\"\n");
    printf("text: \"%s\"\n", des_ctx.output);
}

static inline void get_text(int opt)
{
    if (!optarg)
        pr_err("Doesn't have an input text\n");

    /* 64 bits is 0100 0000 in binary */
    des_ctx.ceil_size = des_ctx.size = strlen(optarg);
    if (des_ctx.ceil_size & 63) {
        des_ctx.ceil_size &= ~63;
        des_ctx.ceil_size += 64;
    }

    des_ctx.input = (uint8_t *)malloc(des_ctx.ceil_size);
    if (!des_ctx.input)
        pr_err("malloc failed (input)\n");
    memset(des_ctx.input, 0, des_ctx.ceil_size);
    
    memcpy(des_ctx.input, optarg, des_ctx.size);

    des_ctx.output = (uint8_t *)malloc(des_ctx.ceil_size);
    if (!des_ctx.output)
        pr_err("malloc failed (output)\n");
    memset(des_ctx.output, 0, des_ctx.ceil_size);

    printf("original text (ceil size %zu, size %zu):\n", des_ctx.ceil_size,
           des_ctx.size);
    printf("\ndigit: \"");
    print_int(des_ctx.input, des_ctx.ceil_size);
    printf("\"\n\n");
}

static void test_en_de(void)
{
    uint8_t *orig_src_p;
    uint8_t *encypted = (uint8_t *)malloc(des_ctx.ceil_size);
    if (!encypted)
        pr_err("malloc failed (encypted)");

    do_des_encrypt();
    
    orig_src_p = des_ctx.input;
    des_ctx.input = des_ctx.output;
    des_ctx.output = encypted;
    
    do_des_decrypt();

    if (strncmp((char *)orig_src_p, (char *)des_ctx.output, 64) == 0)
        printf("Passed\n");

    des_ctx.output = orig_src_p;
    free(encypted);
}

int main(int argc, char *argv[])
{
    int opt;

    while ((opt = getopt(argc, argv, "e:d:a:"))) {
        switch (opt) {
        case 'e':
            get_text(opt);
            do_des_encrypt();
            goto done;
        case 'd':
            get_text(opt);
            do_des_decrypt();
            goto done;
        case 'a':
            get_text(opt);
            test_en_de();
            goto done; 
        default:
            printf("Usage: %s [-e encrypt] [-d decrypt] [-a test encrypt decrypt] text\n",
                   argv[0]);
            pr_err("Unkown option\n");
        }
    }

done:
    free(des_ctx.input);
    free(des_ctx.output);
    return 0;
}
