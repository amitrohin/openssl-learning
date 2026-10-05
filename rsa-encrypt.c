/* ~$ man PEM_read_PUBKEY
 * ~$ man EVP_PKEY_CTX_new_from_pkey
 * ~$ man EVP_PKEY_encrypt_init
 * ~$ man EVP_PKEY_CTX_set_rsa_padding
 * ~$ man EVP_PKEY_get_size
 * ~$ man EVP_PKEY_encrypt
 * ~$ man provider-asym_cipher
 * 
 * Программа будет принимать три аргумента в командной строке:
 * 1) имя входного файла;
 * 2) имя выходного файла;
 * 3) имя файла с открытым ключом RSA.
 * 
 * Общий план реализации:
 * 1) загрузить открытый ключ RSA из файла;
 * 2) создать контекст EVP_PKEY с этим ключом;
 * 3) инициализировать контекст EVP_PKEY для шифрования и установить
 *    режим дополнения OAEP;
 * 4) прочитать открытый текст из входного файла;
 * 5) зашифровать открытый текст;
 * 6) записать шифртекст в выходной файл
 * 
 * ~$ ./rsa-encrypt infile outfile rsa_pubkey.pem
 *
 * ~$ ./encrypt infile outfile \
 *          e40e5be6793b65f61ea263d73b8a6b0d093b3e7560b71a90f2e3fd33e9cbeb24
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
    char const *pubkey_pem = argv[3];

    FILE *ifp = NULL;
    FILE *ofp = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *msg = NULL, *rsa_buf = NULL;

    ifp = fopen(in_file, "rb");
    if (!ifp)
        egoto2(E0, errno, "Could not open input file \"%s\".", in_file);
    ofp = fopen(out_file, "wb");
    if (!ofp)
        egoto2(E0, errno, "Could not open output file \"%s\".", out_file);

    do {
        FILE *fp = fopen(pubkey_pem, "rb");
        if (!fp)
            egoto2(E0, errno, "Could not open public key file: \"%s\".",
                pubkey_pem);
        pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
        fclose(fp);
        if (!pkey) {
            ERR_print_errors_fp(stderr);
            egoto(E0, "PEM_read_PUBKEY(): %s: Failed.", pubkey_pem);
        }
    } while (0);

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "EVP_PKEY_CTX_new_from_pkey() failed.");
    }

    /* man provider-asym_cipher */
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
    if (EVP_PKEY_encrypt_init_ex(ctx, params) != 1) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "EVP_PKEY_encrypt_init_ex() failed.");
    }

    int rsa_size = EVP_PKEY_get_size(pkey);
    int rsa_bits = EVP_PKEY_get_bits(pkey);
    int rsa_security_bits = EVP_PKEY_get_security_bits(pkey);
    printf(
        "EVP_PKEY_get_size():          %4d bytes\n"
        "EVP_PKEY_get_bits():          %4d bits\n"
        "EVP_PKEY_get_security_bits(): %4d bits\n",
        rsa_size, rsa_bits, rsa_security_bits
    );

    int hlen;
    do {
        EVP_MD const *md;
        /* [!] md не нужно освобождать */
        if (EVP_PKEY_CTX_get_rsa_oaep_md(ctx, &md) != 1) {
            ERR_print_errors_fp(stderr);
            egoto(E0, "EVP_PKEY_CTX_get_rsa_oaep_md() failed");
        }
        hlen = EVP_MD_get_size(md);
    } while (0);
    
    int rsa_maxmsg = rsa_size - 2 * hlen - 2;
    printf("RSA maximal message length is %d bytes.\n", rsa_maxmsg);

    struct stat sb;
    if (fstat(fileno(ifp), &sb))
        egoto2(E0, errno, "fstat(): %s", in_file);

    size_t msg_size = sb.st_size;
    if (msg_size < 1 || msg_size > rsa_maxmsg)
        egoto(E0, "The text to encrypt must be between 1 and %d bytes "
            "(got %zu bytes).", rsa_maxmsg, msg_size);

    printf("msg_size = %zu\n", msg_size);

    msg = malloc(msg_size);
    if (!msg)
        egoto2(E0, errno, "malloc(): %zu bytes", msg_size);

    size_t n = fread(msg, 1, msg_size, ifp);
    if (ferror(ifp))
        egoto2(E0, errno, "Failed to read \"%s\".", in_file);
    assert(n == msg_size);

    rsa_buf = malloc(rsa_size);
    if (!rsa_buf)
        egoto2(E0, errno, "malloc(): %d bytes", rsa_size);

    size_t rsa_len = rsa_size;

    if (EVP_PKEY_encrypt(ctx, rsa_buf, &rsa_len, msg, msg_size) != 1) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "EVP_PKEY_encrypt() failed.");
    }
    assert(rsa_len == rsa_size);

    fwrite(rsa_buf, 1, rsa_len, ofp);
    if (ferror(ofp))
        egoto2(E0, errno, "Could not write to \"%s\".", out_file);

    free(rsa_buf);
    free(msg);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    fclose(ofp);
    fclose(ifp);
    return 0;

E0: if (rsa_buf)
        free(rsa_buf);
    if (msg)
        free(msg);
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
