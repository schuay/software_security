#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

static void
hexdump(const char *p,
        const int n)
{
    for (int i = 0; i < n; i++) {
        printf("%08x ", p[i]);
    }
    printf("\n");
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
    unsigned char *p = fn(d, n, md);
    printf("POST SHA1(%s, %d, %s) = %s\n", d, n, md, p);
    hexdump(md, 20);
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
    hexdump(outm, *outl);
    return p;
}
