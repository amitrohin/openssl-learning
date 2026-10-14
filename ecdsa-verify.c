/* $ man PEM_read_PrivateKey
 * $ man PEM_read_PUBKEY
 * $ man EVP_DigestSignInit_ex
 * $ man EVP_DigestVerifyInit_ex
 * 
 * Программа будет принимать три аргумента в командной строке:
 * 1) имя файла для которого нужн опроверить погдпись;
 * 2) имя файла содержащего подпись;
 * 3) имя файла с публичным ключем.
 * 
 * Общий план реализации:
 * 1. Прочитать подпись.
 * 1. Загрузить публичный ключ ecdsa из файла;
 * 2. Создать EVP_MD_CTX, который используется для подписания:
 * 3. Инициализировать контекст EVP_MD_CTX
 *      - определить функцию хеширования.
 *      - указать публичный ключ.
 * 4. Читать открытый текст частями из входного файла и помещать в
 *    контекст подписания.
 * 6. Завершить процедуру подписания со сравнением полученой подписи с
 *    взятой из файла с подписью.
 * 7. Записать подпись в выходной файл.
 * 
 * ~$ ./ecdsa-sign infile outfile ec_keypair.pem
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/pem.h>

#include "foo.h"

int main(int argc, char *argv[]) {
    char const *txt_file = argv[1];
    char const *sig_file = argv[2];
    char const *pubkey_pem = argv[3];

    FILE *txt_fp = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;

    size_t sig_len;
    unsigned char *signature = NULL;

    txt_fp = fopen(txt_file, "rb");
    if (!txt_fp)
        egoto2(E0, errno, "Could not open text file \"%s\".", txt_file);

    do {
        __label__ E1;
        FILE *fp = NULL;
        struct stat sb;
        size_t n;

        fp = fopen(sig_file, "rb");
        if (!fp)
            egoto2(E1, errno, "Could not open signature file \"%s\".", sig_file);
        if (fstat(fileno(fp), &sb))
            egoto2(E1, errno, "fstat(): %s", sig_file);
        signature = malloc(sb.st_size);
        if (!signature)
            egoto2(E1, errno, "malloc(): %zu bytes", sb.st_size);
        sig_len = sb.st_size;

        n = fread(signature, 1, sig_len, fp);
        if (ferror(fp))
            egoto2(E1, errno, "fread(): %s", sig_file);
        assert(n == sig_len);

        fclose(fp);
        break;

    E1: fclose(fp);
        goto E0;
    } while (0);

    do {
        FILE *fp = fopen(pubkey_pem, "rb");
        if (!fp)
            egoto2(E0, errno, "Could not open public key file: \"%s\".",
                pubkey_pem);
        /* EVP_PKEY *PEM_read_PUBKEY(FILE *fp, EVP_PKEY **x,
         *                           pem_password_cb *cb, void *u);
         */
        pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
        fclose(fp);
        if (!pkey)
            ossl_egoto(E0, "PEM_read_PUBKEY(): %s", pubkey_pem);
    } while (0);

    int pkey_size = EVP_PKEY_get_size(pkey);
    int pkey_bits = EVP_PKEY_get_bits(pkey);
    int pkey_security_bits = EVP_PKEY_get_security_bits(pkey);
    printf(
        "EVP_PKEY_get_size():          %4d bytes\n"
        "EVP_PKEY_get_bits():          %4d bits\n"
        "EVP_PKEY_get_security_bits(): %4d bits\n",
        pkey_size, pkey_bits, pkey_security_bits
    );

    ctx = EVP_MD_CTX_new();
    if (!ctx)
        ossl_egoto(E0, "EVP_MD_CTX_new()");

    /* int EVP_DigestSignInit_ex(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
     *                           const char *mdname, OSSL_LIB_CTX *libctx,
     *                           const char *props, EVP_PKEY *pkey,
     *                           const OSSL_PARAM params[]);
     */
    if (EVP_DigestVerifyInit_ex(ctx, NULL, OSSL_DIGEST_NAME_SHA3_512, NULL,
                  NULL, pkey, NULL) != 1)
        ossl_egoto(E0, "EVP_DigestVerifyInit_ex()");

    for (;;) {
        char buf[0x1000];
        size_t n = fread(buf, 1, sizeof buf, txt_fp);
        if (!n) {
            if (ferror(txt_fp))
                egoto2(E0, errno, "Failed to read \"%s\".", txt_file);
            break;
        }
        if (EVP_DigestVerifyUpdate(ctx, buf, n) != 1)
            ossl_egoto(E0, "EVP_DigestVerifyUpdate()");
    }

    if (EVP_DigestVerifyFinal(ctx, signature, sig_len) != 1)
        ossl_egoto(E0, "EVP_DigestVerifyFinal(): Signature Verification Failure");

    printf("Signature Verified Successfully\n");

    free(signature);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    fclose(txt_fp);
    return 0;

E0: if (signature)
        free(signature);
    if (ctx)
        EVP_MD_CTX_free(ctx);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (txt_fp)
        fclose(txt_fp);
    return 1;
}

// vi: ts=4:sts=4:sw=4:et:nu:noai:nosi:syn=off
