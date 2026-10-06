#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "foo.h"

int main(int argc, char *argv[]) {
    char const *in_file = argv[1];
    char const *out_file = argv[2];
    char const *pkey_file = argv[3];

    FILE *ifp = NULL;
    FILE *ofp = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int hlen = 0;
    int rsa_len = 0;
    unsigned char *rsa_msg = NULL;
    size_t msg_len = 0;
    unsigned char *msg = NULL;

    ifp = fopen(in_file, "rb");
    if (!ifp)
        egoto2(E0, errno, "Could not open input file \"%s\".", in_file);
    ofp = fopen(out_file, "wb");
    if (!ofp)
        egoto2(E0, errno, "Could not open output file \"%s\".", out_file);

    /* Прочитаем приватный ключ */
    do {
        FILE *fp = fopen(pkey_file, "rb");
        if (!fp)
            egoto2(E0, errno, "Could not open private key file: \"%s\".",
                pkey_file);
        pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
        if (!pkey)
            ossl_egoto(E0, "PEM_read_PrivateKey(): %s", pkey_file);
    } while (0);

    /* Создадим контекст для расшифровывания на основе прочитанного ключа */
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (!ctx)
        ossl_egoto(E0, "EVP_PKEY_CTX_new_from_pley()");

    /* Нужно проинициализировать созданный контекст. В нашем случае это
     * тип дополнения (хотим oaep), и sha2-256 - для дополнения блоков до
     * нужного размера (по умолчанию использовался бы sha1).
     *
     * man provider-asym_cipher
     */
    int padding = RSA_PKCS1_OAEP_PADDING;
    OSSL_PARAM params[] = {
        { 
            .key = OSSL_ASYM_CIPHER_PARAM_PAD_MODE,     // "pad-mode"

            /* [!] работают оба варианта, но мне второй больше нравится:
             * .data_type = OSSL_PARAM_UTF8_STRING,
             * .data = OSSL_PKEY_RSA_PAD_MODE_OAEP,        // "oaep"
             * .data_size = sizeof OSSL_PKEY_RSA_PAD_MODE_OAEP - 1,
             */
            .data_type = OSSL_PARAM_INTEGER,
            .data = &padding,
            .data_size = sizeof(padding),

            .return_size = 0
        }, {
            .key = OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,  // "digest"
            .data_type = OSSL_PARAM_UTF8_STRING,
            .data = OSSL_DIGEST_NAME_SHA2_256,          // "SHA2-256"
            .data_size = sizeof OSSL_DIGEST_NAME_SHA2_256 - 1,
            .return_size = 0
        }, {
            .key = OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,  // "mgf1-digest"
            .data_type = OSSL_PARAM_UTF8_STRING,
            .data = OSSL_DIGEST_NAME_SHA2_256,          // "SHA2-256"
            .data_size = sizeof OSSL_DIGEST_NAME_SHA2_256 - 1,
            .return_size = 0
        },
        OSSL_PARAM_END,
    };
    if (EVP_PKEY_decrypt_init_ex(ctx, params) != 1)
        ossl_egoto(E0, "EVP_PKEY_encrypt_init_ex()");

    /* Определим размеш хэша для sha2-256 (он же sha256) */
    do {
        EVP_MD const *md;
        /* [!] md не нужно освобождать */
        if (EVP_PKEY_CTX_get_rsa_oaep_md(ctx, &md) != 1) {
            ERR_print_errors_fp(stderr);
            egoto(E0, "EVP_PKEY_CTX_get_rsa_oaep_md() failed");
        }
        hlen = EVP_MD_get_size(md);
    } while (0);

    /* Определим размер RSA данных, которые соответствуют sha2-256 */
    rsa_len = EVP_PKEY_get_size(pkey);

    /* Проверим, что размер файла соответствует ожидаемому */
    do {
        struct stat sb;
        if (fstat(fileno(ifp), &sb))
            egoto2(E0, errno, "fstat(): %s", in_file);
        if (sb.st_size != rsa_len)
            egoto(E0, "Invalid RSA decryption input size: expected %d bytes.", rsa_len);
    } while (0);

    /* Выделим буфер для чтения входных зашифрованных данных */
    rsa_msg = malloc(rsa_len);
    if (!rsa_msg)
        egoto2(E0, errno, "malloc(): %d bytes", rsa_len);

    /* Прочитаем */
    do {
        size_t br = fread(rsa_msg, 1, rsa_len, ifp);
        if (ferror(ifp))
            egoto2(E0, errno, "fread(): %s", in_file);
        if (br != rsa_len)
            egoto(E0, "Invalid RSA decryption input size: expected %d bytes.", rsa_len);
    } while(0);

    /* [!] Теперь нужно понять максимальный размер данных после расшифровки.
     * 
     * Если рассчитать точный размер и подать буфер размером в 446 байтов, то
     * будет ошибка:
     *      Maximal message length after decryption is 446 bytes.
     *      main(),137: EVP_PKEY_decrypt(): .../rsa_enc.c:257: rsa_decrypt(): \
     *          err=0x1c80008e (lib=0x39, reason=0x8e, fatal=0), \
     *          libname=Provider routines, reason=bad length
     * НО! Если пойти по примеру из man EVP_PKEY_decrypt и сначала запросить
     * размер буфера, а потом повторить уже с полученным размером, то все 
     * отработает:
     *      Maximal message length after decryption is 446 bytes.
     *      [EXPECTED] Decrypted message length 512 bytes.
     *      Decrypted message length 32 bytes.
     * Тут 512 байтов - это тот размер буфера, который возвращает первый
     * вызов, а 32 байта - это второй вызов c фактической расшифровкой данных.
     */
    size_t maxmsg = rsa_len - 2 * hlen - 2;
    printf("Maximal message length after decryption is %zu bytes.\n", maxmsg);

    if (EVP_PKEY_decrypt(ctx, NULL, &msg_len, rsa_msg, rsa_len) != 1)
        ossl_egoto(E0, "EVP_PKEY_decrypt()");

    printf("[EXPECTED] Decrypted message length %zu bytes.\n", msg_len);

    msg = malloc(msg_len);
    if (!msg)
        egoto2(E0, errno, "malloc(): %zu bytes", maxmsg);

    if (EVP_PKEY_decrypt(ctx, msg, &msg_len, rsa_msg, rsa_len) != 1)
        ossl_egoto(E0, "EVP_PKEY_decrypt()");

    printf("Decrypted message length %zu bytes.\n", msg_len);

    fwrite(msg, 1, msg_len, ofp);
    if (ferror(ofp))
        egoto2(E0, errno, "fwrite(): %s", out_file);

    free(msg);
    free(rsa_msg);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    fclose(ofp);
    fclose(ifp);
    return 0;

E0: if (msg)
        free(msg);
    if (rsa_msg)
        free(rsa_msg);
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (ofp)
        fclose(ofp);
    if (ifp)
        fclose(ifp);
    return 1;
}
// vi: ts=4:sts=4:sw=4:et:nu:noai:nosi:syn=off
