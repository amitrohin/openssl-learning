/* 1. Сначала необходимо инициализировать контекст вычисления хеш значения.
 * 2. Затем нужно помещать в контексте данные порциями, читая их из входного
 *    файла.
 * 3. Далее нужно завершить вычисление и получить хешзначение.
 * 4. Наконец, необходимо вывести вычисленное хешзначение на stdout.
 *
 * ~$ ./digest infile
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>

#include "foo.h"

#define SHA3_256_HASH_LENGTH (256 / 8)

static int digest(FILE* fp, unsigned char hash[EVP_MAX_MD_SIZE],
                  unsigned int *hlen);

int main(int argc, char *argv[]) {
    char const *in_file = argv[1];
    FILE *fp = NULL;
    unsigned int hlen = 0;
    unsigned char hash[EVP_MAX_MD_SIZE];

    fp = fopen(in_file, "r");
    if (!fp)
        egoto2(E0, errno, "Could not open input file \"%s\".", in_file);
    if (digest(fp, hash, &hlen))
        goto E0;
    for (int i = 0; i < hlen; i++)
        printf("%02x", hash[i]);
    printf("  %s\n", in_file);
    fclose(fp);
    return 0;

E0: if (fp)
        fclose(fp);
    return 1;
}

static int digest(FILE *fp, unsigned char hash[EVP_MAX_MD_SIZE],
                  unsigned int *hlen)
{
    EVP_MD_CTX *ctx = NULL;
    EVP_MD *md = NULL;

    /* Получаем реализацию шифра SHA3-256.
     * EVP_MD *EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
     *                      const char *properties);
     */
    md = EVP_MD_fetch(NULL, "SHA3-256", NULL);
    if (!md) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "EVP_MD_fetch(): Failed to get SHA3-256.");
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "Could not allocate EVP_MD_CTX.");
    }

    /* int EVP_DigestInit_ex2(EVP_MD_CTX *ctx, const EVP_MD *type,
     *                        const OSSL_PARAM params[]);
     */
    if (EVP_DigestInit_ex2(ctx, md, NULL) != 1) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "Digest init failed.");
    }

    while (1) {
        unsigned char buf[1024];
        size_t br = fread(buf, 1, sizeof buf, fp);
        if (!br) {
            if (ferror(fp))
                egoto2(E0, errno, "Error reading input file.");
            break;
        }

        if (EVP_DigestUpdate(ctx, buf, br) != 1) {
            ERR_print_errors_fp(stderr);
            egoto(E0, "Digest update failed.");
        }
    }

    /* int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
     *
     * Retrieves the digest value from ctx and places it in md. If the s
     * parameter is not NULL then the number of bytes of data written (i.e.
     * the length of the digest) will be written to the integer at s, at
     * most EVP_MAX_MD_SIZE bytes will be written unless the digest
     * implementation allows changing the digest size and it is set to a
     * larger value by the application. After calling EVP_DigestFinal_ex()
     * no additional calls to EVP_DigestUpdate() can be made, but
     * EVP_DigestInit_ex2() can be called to initialize a new digest
     * operation. ctx MUST NOT be NULL.
     */
    if (EVP_DigestFinal(ctx, hash, hlen) != 1) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "Could not finalize ddigest.");
    }

    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);
    return 0;
    
E0: if (md)
        EVP_MD_free(md);
    if (ctx)
        EVP_MD_CTX_free(ctx);
    return -1;
}

// vi: ts=4:sts=4:sw=4:et:nu:noai:nosi:syn=off
