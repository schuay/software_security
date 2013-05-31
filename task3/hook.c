#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

static void
hexdump(const char *label,
        const char *p,
        const int n)
{
    printf("hexdump (%s): ", label);
    for (int i = 0; i < n; i++) {
        printf("%02x ", p[i] & 0xFF);
    }
    printf("\n");
}

int gettimeofday(void *tp, void *tzp)
{
	static int (*fn)(void *, void *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "gettimeofday");
    }
    printf("PRE  gettimeofday(%x, %x)\n", tp, tzp);
    const char *time = getenv("REAL_TIME");
    int p = fn(tp, tzp);

    if (time != NULL) {
        int t = strtol(time, NULL, 16);
        printf("Overriding time with: %x\n", t);
        int *tpp = tp;
        *tpp = t;
    }

    printf("POST gettimeofday(%x, %x) = %d\n", tp, tzp, p);
    printf("tp: %x\n", *((int *)tp));
    return p;
}

unsigned char *SHA1(const unsigned char *d,
                    unsigned long n,
                    unsigned char *md)
{    
	static unsigned char *(*fn)(const unsigned char *, unsigned long, unsigned char *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "SHA1");
    }
    printf("PRE  SHA1(%s, %d, %s)\n", d, n, md);
    hexdump("d", d, n);
    const unsigned char d_[] = { 0xde, 0xc0, 0xad, 0xde };
    hexdump("d_", d_, n);
    unsigned char *p = fn(d_, n, md);
    printf("POST SHA1(%s, %d, %s) = %s\n", d, n, md, p);
    hexdump("md", md, 20);
    return p;
}

typedef void EVP_CIPHER_CTX;

int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                int *outl)
{
	static int (*fn)(EVP_CIPHER_CTX *ctx, unsigned char *, int *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "EVP_DecryptFinal_ex");
    }
    printf("PRE  EVP_DecryptFinal_ex(%x, %s, %d)\n", ctx, outm, *outl);
    int p = fn(ctx, outm, outl);
    printf("POST EVP_DecryptFinal_ex(%x, %s, %d) = %p\n", ctx, outm, *outl, p);
    hexdump("outm", outm, *outl);
    return p;
}
