/* 1. Сгенерировать случайный IV и записать его в выходной файл.
 * 2. Инициализировать шифрование.
 * 3. Шифровать порциями, читая порции открытого текста из входного
 *    файла и записывая результирующий шифртекст в выходной файл.
 * 4. Завершить шифрование.
 * 5. Получить аутентификационный жетон и записать его в выходной файл.
 *
 * формат файла:
 *    IV[12], зашифрованный текст[??], аутентификационный жетон[16]
 * [!] закрытой информацией является только ключ.
 *
 * ~$ key_hex=$(openssl rand -hex 32)
 * ~$ ./encrypt infile outfile "$key_hex"
 *
 * ~$ ./encrypt infile outfile \
 *          e40e5be6793b65f61ea263d73b8a6b0d093b3e7560b71a90f2e3fd33e9cbeb24
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/core_names.h>

#include "foo.h"

static unsigned char key[32];  /* длина ключа должна быть 256 бит */

static int encrypt(FILE* ifp, FILE* ofp, const unsigned char* key);

int main(int argc, char *argv[]) {
    char const *in_file = argv[1];
    char const *out_file = argv[2];
    char const *key_hex = argv[3];

    FILE *ifp = NULL;
    FILE *ofp = NULL;

    do {
        /* Проверим key_hex и посчитаем его длину функцией
         * OPENSSL_hexstr2buf_ex(). Первый параметр должен быть NULL, чтобы
         * посчитать длину.
         */
        size_t key_len;
        if (!OPENSSL_hexstr2buf_ex(NULL, 0, &key_len, key_hex, 0)) {
            ERR_print_errors_fp(stderr);
            egoto(E0, "Illegal key syntax: \"%s\".", key_hex);
        }
        if (key_len != sizeof key)
            egoto(E0, "Wrong key \"%s\", must be %zu hex digits (not %zu).",
                key_hex, 2 * sizeof key, key_len);
        OPENSSL_hexstr2buf_ex(key, sizeof key, NULL, key_hex, 0);
    } while (0);

    ifp = fopen(in_file, "r");
    if (!ifp)
        egoto2(E0, errno, "Could not open input file \"%s\".", in_file);
    ofp = fopen(out_file, "w");
    if (!ofp)
        egoto2(E0, errno, "Could not open output file \"%s\".", out_file);

    if (encrypt(ifp, ofp, key))
        goto E0;

    fclose(ofp);
    fclose(ifp);
    return 0;

E0: if (ofp)
        fclose(ofp);
    if (ifp)
        fclose(ifp);
#if 0
    if (key)
        OPENSSL_free(key);
#endif
    return 1;
}

static int encrypt(FILE *ifp, FILE *ofp, unsigned char const *key) {
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    unsigned char iv[12];       /* 96 бит (32 бита будет добавлять счетчик) */
    unsigned char auth_tag[16]; /* аутентификационный жетон */
    unsigned char ibuf[8192], obuf[8192 + 16];

    /* 1. Получим случайную последовательность из 96 битов в iv.
     *
     * int RAND_bytes(unsigned char *buf, int num);
     *
     * RAND_bytes() and RAND_priv_bytes() return 1 on success, -1 if not
     * supported by the current RAND method, or 0 on other failure. The error
     * code can be obtained by ERR_get_error(3).
     */
    if (RAND_bytes(iv, sizeof iv) != 1) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "Failed to generate initialization vector (IV).");
    }

    /* 2. Сохраним iv в выходной файл.
     */
    if (fwrite(iv, 1, sizeof iv, ofp) != sizeof iv)
        egoto2(E0, errno, "Could not write IV to output file.");

    /* 3. Получаем реализацию шифра AES-256-GCM из провайдера.
     *
     * EVP_CIPHER *EVP_CIPHER_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
     *                              const char *properties);
     *
     * Fetches the cipher implementation for the given algorithm from any
     * provider offering it, within the criteria given by the properties.
     * See "ALGORITHM FETCHING" in crypto(7) for further information.
     *
     * The returned value must eventually be freed with EVP_CIPHER_free().
     * Fetched EVP_CIPHER structures are reference counted.
     *
     * EVP_CIPHER_fetch() returns a pointer to a EVP_CIPHER for success and NULL
     * for failure.
     *
     *  - 1-й аргумент (NULL)   — библиотечный контекст по умолчанию.
     *  - 2-й аргумент          — имя алгоритма.
     *  - 3-й аргумент (NULL)   — свойства (properties), здесь не нужны.
     */
    cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    if (!cipher) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "EVP_CIPHER_fetch(): Failed to get AES-256-GCM cipher.");
    }

    /* 4. Создадим контекст.
     */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "Could not allocate EVP_CIPHER_CTX.");
    }

    /* 5. Проинициализируем контекст.
     *
     * int EVP_EncryptInit_ex2(EVP_CIPHER_CTX *ctx,
     *                         const EVP_CIPHER *type,
     *                         const unsigned char *key,
     *                         const unsigned char *iv,
     *                         const OSSL_PARAM params[]);
     *
     * Sets up cipher context ctx for encryption with cipher type. ctx MUST
     * NOT be NULL.  type is typically supplied by calling
     * EVP_CIPHER_fetch(). type may also be set using legacy functions such
     * as EVP_aes_256_cbc(), but this is not recommended for new
     * applications. key is the symmetric key to use and iv is the IV to use
     * (if necessary), the actual number of bytes used for the key and IV
     * depends on the cipher. The parameters params will be set on the
     * context after initialisation. It is possible to set all parameters to
     * NULL except type in an initial call and supply the remaining
     * parameters in subsequent calls, all of which have type set to NULL.
     * This is done when the default cipher parameters are not appropriate.
     * For EVP_CIPH_GCM_MODE the IV will be generated internally if it is
     * not specified.
     *
     * See OSSL_PARAM(3).
     *
     * EVP_EncryptInit_ex2(), EVP_EncryptUpdate() and EVP_EncryptFinal_ex()
     * return 1 for success and 0 for failure.
     */
    if (EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) != 1) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "Could not initialize encription.");
    }

    for (;;) {
        size_t br = fread(ibuf, 1, sizeof ibuf, ifp);
        if (!br) {
            if (ferror(ifp))
                egoto2(E0, errno, "Error reading input file.");
            break;
        }

        /* Шифруем прочитанный буфер.
         *
         * int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
         *                       int *outl, const unsigned char *in, int inl);
         *
         * Encrypts inl bytes from the buffer in and writes the encrypted
         * version to out. The pointers out and in may point to the same
         * location, in which case the encryption will be done in-place.
         * However, in-place encryption is guaranteed to work only if the
         * encryption context (ctx) has processed data in multiples of the block
         * size. If the context contains an incomplete data block from previous
         * operations, in-place encryption will fail. ctx MUST NOT be NULL.
         *
         * If out and in point to different locations, the two buffers must be
         * disjoint, otherwise the operation might fail or the outcome might be
         * undefined.
         *
         * This function can be called multiple times to encrypt successive
         * blocks of data. The amount of data written depends on the block
         * alignment of the encrypted data.  For most ciphers and modes, the
         * amount of data written can be anything from zero bytes to (inl +
         * cipher_block_size - 1) bytes.  For wrap cipher modes, the amount of
         * data written can be anything from zero bytes to (inl rounded up to
         * cipher_block_size + cipher_block_size) bytes.  For stream ciphers,
         * the amount of data written can be anything from zero bytes to inl
         * bytes.  Thus, the buffer pointed to by out must contain sufficient
         * room for the operation being performed.  The actual number of bytes
         * written is placed in outl.
         *
         * If padding is enabled (the default) then EVP_EncryptFinal_ex()
         * encrypts the "final" data, that is any data that remains in a partial
         * block.  It uses standard block padding (aka PKCS padding) as
         * described in the NOTES section, below. The encrypted final data is
         * written to out which should have sufficient space for one cipher
         * block. The number of bytes written is placed in outl. After this
         * function is called the encryption operation is finished and no
         * further calls to EVP_EncryptUpdate() should be made.
         *
         * If padding is disabled then EVP_EncryptFinal_ex() will not encrypt
         * any more data and it will return an error if any data remains in a
         * partial block: that is if the total data length is not a multiple of
         * the block size.
         *
         * EVP_EncryptInit_ex2(), EVP_EncryptUpdate() and EVP_EncryptFinal_ex()
         * return 1 for success and 0 for failure.
         */
        int be = 0;
        if (EVP_EncryptUpdate(ctx, obuf, &be, ibuf, br) != 1) {
            ERR_print_errors_fp(stderr);
            egoto(E0, "Could not encrypt data chunk.");
        }

        unsigned char *obuf_ptr = obuf;
        while (be) {
            size_t bw = fwrite(obuf, 1, be, ofp);
            if (ferror(ofp))
                egoto2(E0, errno, "Could not write to output file.");
            obuf_ptr += bw;
            be -= bw;
        }
    }

    /* Финализируем шифрованные данные и добавляем аутентификационный жетон.
     *
     * int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
     *
     * EVP_EncryptFinal(), EVP_DecryptFinal() and EVP_CipherFinal()
     * Identical to EVP_EncryptFinal_ex(), EVP_DecryptFinal_ex() and
     * EVP_CipherFinal_ex(). In previous releases they also cleaned up the
     * ctx, but this is no longer done and EVP_CIPHER_CTX_cleanup() must be
     * called to free any context resources.
     *
     * EVP_EncryptInit_ex2(), EVP_EncryptUpdate() and EVP_EncryptFinal_ex()
     * return 1 for success and 0 for failure.
     */
    int nbytes = 0;
    if (EVP_EncryptFinal(ctx, obuf, &nbytes) != 1) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "Could not finalize encryption.");
    }

    fwrite(obuf, 1, nbytes, ofp);
    if (ferror(ofp))
        egoto2(E0, errno, "Could not write to output file.");


    /* int EVP_CIPHER_CTX_get_params(EVP_CIPHER_CTX *ctx, OSSL_PARAM params[]);
     * 
     * EVP_CIPHER_get_params(), EVP_CIPHER_CTX_get_params() and
     * EVP_CIPHER_CTX_set_params() return 1 for success and 0 for failure.
     *
     * see OSSL_PARAM(3):
     */
    OSSL_PARAM params[] = {
        {
            .key = OSSL_CIPHER_PARAM_AEAD_TAG,
            .data_type = OSSL_PARAM_OCTET_STRING,
            .data = auth_tag,
            .data_size = sizeof auth_tag,
            .return_size = 0
        },
        { NULL, 0, NULL, 0, 0 }
    };
    if (EVP_CIPHER_CTX_get_params(ctx, params) != 1) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "Could not get auth tag GCM.");
    }

    fwrite(auth_tag, 1, sizeof auth_tag, ofp);
    if (ferror(ofp))
        egoto2(E0, errno, "Could not write to output file.");
    
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
    
E0: if (cipher)
        EVP_CIPHER_free(cipher);
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return -1;
}

// vi: ts=4:sts=4:sw=4:et:nu:noai:nosi:syn=off
