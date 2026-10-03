/* salt=$(openssl rand -hex 8)
 * ~$ ./kdf "mysecret" "$salt"
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>

#include "foo.h"

/* Длина возвращаемого ключа для scrypt является переменной. Можно задать её
 * самостоятельно при вызове функции генерации ключа EVP_KDF_derive().
 */

/* [!] OWASP recommended settings: n = 65536, r = 8, p = 1 */
static uint64_t OWASP_scrypt_n = 65536;
static uint32_t OWASP_scrypt_r = 8;
static uint32_t OWASP_scrypt_p = 1;

static int calc_kdf_scrypt(char const *pass, unsigned char const *salt,
    size_t salt_len, unsigned char *key, size_t key_len);

int main(int argc, char *argv[]) {
    char const *pass = argv[1];
    char const *salt_hex = argv[2];
    unsigned char *salt = NULL;
    unsigned char key[256/8];

    long salt_len = 0;
    salt = OPENSSL_hexstr2buf(salt_hex, &salt_len);
    if (!salt) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "Could not parse hex-string of salt.");
    }
    if (calc_kdf_scrypt(pass, salt, salt_len, key, sizeof key))
        goto E0;

    printf("key=hex:");
    for (int i = 0; i < sizeof key; i++)
        printf("%02x", key[i]);
    printf(", pass=\"%s\", salt=hex:%s\n", pass, salt_hex);

    OPENSSL_free(salt);
    return 0;

E0: if (salt)
        OPENSSL_free(salt);
    return 1;
}

static int calc_kdf_scrypt(char const *pass, unsigned char const *salt,
    size_t salt_len, unsigned char *key, size_t key_len)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    /* #define OSSL_KDF_NAME_SCRYPT "SCRYPT" */
    kdf = EVP_KDF_fetch(NULL, OSSL_KDF_NAME_SCRYPT, NULL);
    if (!kdf) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "EVP_KDF_fetch(): Failed to get KDF (Key Derivation Function).");
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "Could not allocate EVP_KDF_CTX.");
    }

    /* The supported parameters are:
     *
     *      "pass" (OSSL_KDF_PARAM_PASSWORD) <octet string>
     *      "salt" (OSSL_KDF_PARAM_SALT) <octet string>
     *          These parameters work as described in "PARAMETERS" in EVP_KDF(3).
     * 
     *      "n" (OSSL_KDF_PARAM_SCRYPT_N) <unsigned integer>
     *      "r" (OSSL_KDF_PARAM_SCRYPT_R) <unsigned integer>
     *      "p" (OSSL_KDF_PARAM_SCRYPT_P) <unsigned integer>
     *      "maxmem_bytes" (OSSL_KDF_PARAM_SCRYPT_MAXMEM) <unsigned integer>
     *          These parameters configure the scrypt work factors N, r, maxmem and
     *          p.  Both N and maxmem_bytes are parameters of type uint64_t.  Both r
     *          and p are parameters of type uint32_t.
     * 
     *      "properties" (OSSL_KDF_PARAM_PROPERTIES) <UTF8 string>
     *          This can be used to set the property query string when fetching the
     *          fixed digest internally. NULL is used if this value is not set.
     * 
     *      The output length of an scrypt key derivation is specified via the
     *      "keylen" parameter to the EVP_KDF_derive(3) function.
     *
     */
    OSSL_PARAM params[] = {
        {
            .key = OSSL_KDF_PARAM_PASSWORD,
            .data_type = OSSL_PARAM_OCTET_STRING,
            .data = (void *)pass,
            .data_size = strlen(pass),
            .return_size = 0
        }, {
            .key = OSSL_KDF_PARAM_SALT,
            .data_type = OSSL_PARAM_OCTET_STRING,
            .data = (void *)salt,
            .data_size = salt_len,
            .return_size = 0
        }, {
            .key = OSSL_KDF_PARAM_SCRYPT_N,
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .data = &OWASP_scrypt_n,
            .data_size = sizeof(OWASP_scrypt_n),
            .return_size = 0
        }, {
            .key = OSSL_KDF_PARAM_SCRYPT_R,
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .data = &OWASP_scrypt_r,
            .data_size = sizeof(OWASP_scrypt_r),
            .return_size = 0
        }, {
            .key = OSSL_KDF_PARAM_SCRYPT_P,
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .data = &OWASP_scrypt_p,
            .data_size = sizeof(OWASP_scrypt_p),
            .return_size = 0
        },
        { NULL, 0, NULL, 0, 0 }
    };
    if (EVP_KDF_derive(kctx, key, key_len, params) != 1) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "EVP_KDF_derive(): failed.");
    }

    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    return 0;
    
E0: if (kdf)
        EVP_KDF_free(kdf);
    if (kctx)
        EVP_KDF_CTX_free(kctx);
    return -1;
}

// vi: ts=4:sts=4:sw=4:et:nu:noai:nosi:syn=off
