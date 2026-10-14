/* $ man PEM_read_PrivateKey
 * $ man PEM_read_PUBKEY
 * $ man EVP_DigestSignInit_ex
 * $ man EVP_DigestVerifyInit_ex
 * 
 * Программа будет принимать три аргумента в командной строке:
 * 1) имя входного файла;
 * 2) имя выходного файла;
 * 3) имя файла с приватным ключем.
 * 
 * Общий план реализации:
 * 1. Загрузить приватный ключ ecdsa из файла;
 * 2. Создать EVP_MD_CTX, который используется для подписания;
 * 3. Инициализировать контекст EVP_MD_CTX
 *      - определить функцию хеширования.
 *      - указать приватный ключ.
 * 4. Читать открытый текст частями из входного файла и помещать в
 *    контекст подписания.
 * 5. Определить длину подписи и выделить для нее память.
 * 6. Завершить процедуру подписания и получить подпись.
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
    char const *in_file = argv[1];
    char const *out_file = argv[2];
    char const *pkey_pem = argv[3];

    FILE *ifp = NULL;
    FILE *ofp = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    unsigned char *signature = NULL;

    ifp = fopen(in_file, "rb");
    if (!ifp)
        egoto2(E0, errno, "Could not open input file \"%s\".", in_file);
    ofp = fopen(out_file, "wb");
    if (!ofp)
        egoto2(E0, errno, "Could not open output file \"%s\".", out_file);

    do {
        FILE *fp = fopen(pkey_pem, "rb");
        if (!fp)
            egoto2(E0, errno, "Could not open private key file: \"%s\".",
                pkey_pem);
        /* EVP_PKEY *PEM_read_PrivateKey(FILE *fp, EVP_PKEY **x,
         *                               pem_password_cb *cb, void *u);
         */
        pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
        if (!pkey)
            ossl_egoto(E0, "PEM_read_PrivateKey(): %s", pkey_pem);
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
    if (EVP_DigestSignInit_ex(ctx, NULL, OSSL_DIGEST_NAME_SHA3_512, NULL,
                  NULL, pkey, NULL) != 1)
        ossl_egoto(E0, "EVP_DigestSignInit_ex()");

    for (;;) {
        char buf[0x1000];
        size_t n = fread(buf, 1, sizeof buf, ifp);
        if (!n) {
            if (ferror(ifp))
                egoto2(E0, errno, "Failed to read \"%s\".", in_file);
            break;
        }
        if (EVP_DigestSignUpdate(ctx, buf, n) != 1)
            ossl_egoto(E0, "EVP_DigestSignUpdate()");
    }

    size_t sig_size;
    if (EVP_DigestSignFinal(ctx, NULL, &sig_size) != 1)
        ossl_egoto(E0, "EVP_DigestSignFinal()");

    signature = malloc(sig_size);
    if (!signature)
        egoto2(E0, errno, "malloc(): %zu bytes", sig_size);

    size_t sig_len = sig_size;
    if (EVP_DigestSignFinal(ctx, signature, &sig_len) != 1)
        ossl_egoto(E0, "EVP_EVP_DigestSignFinal()");

    printf("sig_len/sig_size = %zu/%zu\n", sig_len, sig_size);

    fwrite(signature, 1, sig_len, ofp);
    if (ferror(ofp))
        egoto2(E0, errno, "Could not write to \"%s\".", out_file);

    free(signature);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    fclose(ofp);
    fclose(ifp);
    return 0;

E0: if (signature)
        free(signature);
    if (ctx)
        EVP_MD_CTX_free(ctx);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (ofp)
        fclose(ofp);
    if (ifp)
        fclose(ifp);
    return 1;
}

// vi: ts=4:sts=4:sw=4:et:nu:noai:nosi:syn=off
