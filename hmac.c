#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>

#include "foo.h"

#define HMAC_SHA2_256_LENGTH    (256/8)

static int calc_hmac_sha2_256(FILE* fp, unsigned char *key, size_t klen,
                              unsigned char hmac[HMAC_SHA2_256_LENGTH]);

int main(int argc, char *argv[]) {
    char const *key_hex = argv[1];
    char const *in_file = argv[2];

    FILE *fp = NULL;
    unsigned char *key = NULL;
    unsigned char hmac[HMAC_SHA2_256_LENGTH];

    long klen = 0;
    key = OPENSSL_hexstr2buf(key_hex, &klen);
    if (!key) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "Could not parse key.");
    }

    fp = fopen(in_file, "r");
    if (!fp)
        egoto2(E0, errno, "Could not open input file \"%s\".", in_file);
    if (calc_hmac_sha2_256(fp, key, klen, hmac))
        goto E0;
    for (int i = 0; i < sizeof hmac; i++)
        printf("%02x", hmac[i]);
    printf("  %s\n", in_file);

    OPENSSL_free(key);
    fclose(fp);
    return 0;

E0: if (key)
        OPENSSL_free(key);
    if (fp)
        fclose(fp);
    return 1;
}

static int calc_hmac_sha2_256(
    FILE* fp, unsigned char *key, size_t klen,
    unsigned char hmac[HMAC_SHA2_256_LENGTH])
{
    EVP_MAC_CTX *ctx = NULL;
    EVP_MAC *mac = NULL;

    /* Получаем реализацию шифра SHA2-256.
     * EVP_MAC *EVP_MAC_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
     *                        const char *properties);
     *
     * #define OSSL_MAC_NAME_HMAC           "HMAC"
     */
    mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL);
    if (!mac) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "EVP_MD_fetch(): Failed to get HMAC.");
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "Could not allocate EVP_MAC_CTX.");
    }

    /* int EVP_MAC_init(EVP_MAC_CTX *ctx, const unsigned char *key,
     *                  size_t keylen, const OSSL_PARAM params[]);
     * Если используется HMAC, то параметр, определяющий алгорим шифрования
     * назывется "digest" (например для CMAC, параметр называется "cipher").
     */
    OSSL_PARAM params[] = {
        /* #define OSSL_MAC_PARAM_DIGEST        OSSL_ALG_PARAM_DIGEST
         * #define OSSL_ALG_PARAM_DIGEST        "digest"
         * #define OSSL_DIGEST_NAME_SHA2_256    "SHA2-256"
         */
        {
            .key = OSSL_MAC_PARAM_DIGEST,           /* "digest" */
            .data_type = OSSL_PARAM_UTF8_STRING,
            .data = OSSL_DIGEST_NAME_SHA2_256,      /* "SHA2-256" */
            .data_size = sizeof OSSL_DIGEST_NAME_SHA2_256 - 1,
            .return_size = 0
        },
        { NULL, 0, NULL, 0, 0 }
    };
    if (EVP_MAC_init(ctx, key, klen, params) != 1) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "MAC init failed.");
    }

    while (1) {
        unsigned char buf[1024];
        size_t br = fread(buf, 1, sizeof buf, fp);
        if (!br) {
            if (ferror(fp))
                egoto2(E0, errno, "Error reading input file.");
            break;
        }

        if (EVP_MAC_update(ctx, buf, br) != 1) {
            ERR_print_errors_fp(stderr);
            egoto(E0, "MAC update failed.");
        }
    }

    /* int EVP_MAC_final(EVP_MAC_CTX *ctx, unsigned char *out, size_t *outl,
     *                   size_t outsize);
     * 
     * EVP_MAC_final() does the final computation and stores the result in the
     * memory pointed at by out of size outsize, and sets the number of bytes
     * written in *outl at.  If out is NULL or outsize is too small, then no
     * computation is made.  To figure out what the output length will be and
     * allocate space for it dynamically, simply call with out being NULL and
     * outl pointing at a valid location, then allocate space and make a second
     * call with out pointing at the allocated space.
     */
    size_t nbytes;
    if (EVP_MAC_final(ctx, hmac, &nbytes, HMAC_SHA2_256_LENGTH) != 1) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "Could not finalize hmac.");
    }
    assert(nbytes == HMAC_SHA2_256_LENGTH);

    EVP_MAC_free(mac);
    EVP_MAC_CTX_free(ctx);
    return 0;
    
E0: if (mac)
        EVP_MAC_free(mac);
    if (ctx)
        EVP_MAC_CTX_free(ctx);
    return -1;
}

// vi: ts=4:sts=4:sw=4:et:nu:noai:nosi:syn=off
