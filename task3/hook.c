#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#define DEBUG(p)

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
    DEBUG(printf("PRE  gettimeofday(%x, %x)\n", tp, tzp);)
    const char *time = getenv("REAL_TIME");
    int p = fn(tp, tzp);

    if (time != NULL) {
        int t = strtol(time, NULL, 16);
        DEBUG(printf("Overriding time with: %x\n", t);)
        int *tpp = tp;
        *tpp = t;
    } else {
        DEBUG(printf("Overriding time with: %x\n", 0xaf6a0000);)
        int *tpp = tp;
        *tpp = 0xaf6a0000;
    }

    DEBUG(printf("POST gettimeofday(%x, %x) = %d\n", tp, tzp, p);)
    DEBUG(printf("tp: %x\n", *((int *)tp));)
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
    DEBUG(printf("PRE  SHA1(%s, %d, %s)\n", d, n, md);)
    DEBUG(hexdump("d", d, n);)
    unsigned char *p = fn(d, n, md);
    DEBUG(printf("POST SHA1(%s, %d, %s) = %s\n", d, n, md, p);)
    DEBUG(hexdump("md", md, 20);)
    return p;
}

typedef void EVP_CIPHER_CTX;

int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                        int *outl, unsigned char *in, int inl)
{
	static int (*fn)(EVP_CIPHER_CTX *ctx, unsigned char *, int *, unsigned char *, int) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "EVP_DecryptUpdate");
    }
    DEBUG(printf("PRE  EVP_DecryptUpdate(%x, %s, %d, %x, %x)\n", ctx, out, *outl, in, inl);)
    int p = fn(ctx, out, outl, in, inl);
    DEBUG(printf("POST EVP_DecryptUpdate(%x, %x: %s, %d, %x, %x) = %p\n", ctx, out, out, *outl, in, inl, p);)
    return p;
}

int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                int *outl)
{
	static int (*fn)(EVP_CIPHER_CTX *ctx, unsigned char *, int *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "EVP_DecryptFinal_ex");
    }
    DEBUG(printf("PRE  EVP_DecryptFinal_ex(%x, %s, %d)\n", ctx, outm, *outl);)
    int p = fn(ctx, outm, outl);
    DEBUG(printf("POST EVP_DecryptFinal_ex(%x, %s, %d) = %p\n", ctx, outm, *outl, p);)
    DEBUG(hexdump("outm", outm, *outl);)
    return p;
}
