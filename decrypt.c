/* 1. Прочитать IV из входного файла.
 * 2. Инициализировать расшифрование.
 * 3. Расшифровывать порциями, читая порции шифртекста из входного
 *    файла и записывая результирующие порции открытого текста в вы
 *    ходной файл.
 * 4. Прочитать аутентификационный жетон из входного файла и поместить
 *    его в контекст шифра.
 * 5. Завершить расшифрование.
 *
 * формат входного шифрованного файла:
 *    IV[12], зашифрованный текст[??], аутентификационный жетон[16]
 *
 * [!] закрытой информацией является только ключ.
 *
 * ~$ ./decrypt infile outfile key
 *
 * Example:
 * ~$ ./decrypt crypted_infile decrypted_outfile \
 *          e40e5be6793b65f61ea263d73b8a6b0d093b3e7560b71a90f2e3fd33e9cbeb24
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

static unsigned char key[32];  /* длина ключа должна быть 256 бит */

static int decrypt(FILE* ifp, FILE* ofp, const unsigned char* key);

int main(int argc, char *argv[]) {
    char const *in_file = argv[1];
    char const *out_file = argv[2];
    char const *key_hex = argv[3];

    FILE *ifp = NULL;
    FILE *ofp = NULL;

    do {
        /* Проверим key_hex и посчитаем его длину функцией
         * int OPENSSL_hexstr2buf_ex(unsigned char *buf, size_t buf_n, long *buflen,
         *                           const char *str, const char sep);
         * [!] Первый параметр должен быть NULL, чтобы посчитать длину.
         * [!] Если бы мы использовали:
         *     unsigned char *OPENSSL_hexstr2buf(const char *str, long *len);
         * то выделенный буфер, который возвращает эта функция, нужно
         * освобождать через OPENSSL_free().
         *
         * OPENSSL_hexstr2buf_ex() decodes the hex string str and places the
         * resulting string of bytes in the given buf.  The character sep is the
         * separator between the bytes, setting this to '\0' means that there is no
         * separator.  buf_n gives the size of the buffer.  If buflen is not NULL,
         * it is filled in with the result length.  To find out how large the result
         * will be, call this function with NULL for buf.  Colons between
         * two-character hex "bytes" are accepted and ignored.  An odd number of hex
         * digits is an error.
         *
         * OPENSSL_buf2hexstr_ex() and OPENSSL_hexstr2buf_ex() return 1 on success,
         * or 0 on error.
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

    if (decrypt(ifp, ofp, key))
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

/* формат входного шифрованного файла:
 *    IV[12], зашифрованный текст[??], аутентификационный жетон[16]
 */
static int decrypt(FILE *ifp, FILE *ofp, unsigned char const *key) {
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    unsigned char iv[12];       /* 96 бит (32 бита будет добавлять счетчик) */
    unsigned char auth_tag[16]; /* аутентификационный жетон */
    unsigned char ibuf[8192], obuf[8192 + 16];

    /* Прочитаем IV из входного файла.
     */
    if (fread(iv, 1, sizeof iv, ifp) != sizeof iv) {
        if (ferror(ifp))
            egoto2(E0, errno, "Could not read IV from input file.");
        else
            egoto(E0, "Could not read IV from input file.");
    }

    /* Получаем реализацию шифра AES-256-GCM из провайдера.
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

    /* Создадим контекст.
     */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "Could not allocate EVP_CIPHER_CTX.");
    }

    /* Проинициализируем контекст.
     *
     * int EVP_DecryptInit_ex2(EVP_CIPHER_CTX *ctx,
     *                         const EVP_CIPHER *type,
     *                         const unsigned char *key,
     *                         const unsigned char *iv,
     *                         const OSSL_PARAM params[]);
     *
     * EVP_DecryptInit_ex2(), EVP_DecryptInit_ex(), EVP_DecryptUpdate() and
     * EVP_DecryptFinal_ex()
     *    These functions are the corresponding decryption operations.
     *     EVP_DecryptFinal() will return an error code if padding is enabled
     *     and the final block is not correctly formatted. The parameters and
     *     restrictions are identical to the encryption operations. ctx MUST NOT
     *     be NULL.
     *
     * Переделано из описания EVP_EncryptInit_ex2():
     * Sets up cipher context ctx for decryption with cipher type. ctx MUST
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
    if (EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL) != 1) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "Could not initialize encription.");
    }

    struct stat sb;
    if (fstat(fileno(ifp), &sb))
        egoto2(E0, errno, "Could not stat input file.");
    if (sb.st_size < sizeof iv + sizeof auth_tag)
        egoto(E0, "Input file is too short.");

    size_t data_size = sb.st_size - (sizeof iv + sizeof auth_tag);
    while (data_size) {
        size_t ibuf_size = sizeof ibuf;
        if (ibuf_size > data_size)
            ibuf_size = data_size;
        size_t br = fread(ibuf, 1, ibuf_size, ifp);
        if (!br) {
            if (ferror(ifp))
                egoto2(E0, errno, "Error reading input file.");
            break;
        }
        data_size -= br;

        /* Расшифруем прочитанный буфер.
         *
         * int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
         *                       int *outl, const unsigned char *in, int inl);
         *
         * EVP_DecryptUpdate() return 1 for success and 0 for failure.
         */
        int obuf_size = 0;
        if (EVP_DecryptUpdate(ctx, obuf, &obuf_size, ibuf, br) != 1) {
            ERR_print_errors_fp(stderr);
            egoto(E0, "Could not decrypt data chunk.");
        }

        unsigned char *obuf_ptr = obuf;
        while (obuf_size) {
            size_t bw = fwrite(obuf, 1, obuf_size, ofp);
            if (ferror(ofp))
                egoto2(E0, errno, "Could not write to output file.");
            obuf_ptr += bw;
            obuf_size -= bw;
        }
    }

    /* После чтения данных идет аутентификационный жетон.
     */
    if (fread(auth_tag, 1, sizeof auth_tag, ifp) != sizeof auth_tag)
        egoto2(E0, errno, "Could not read authentication tag from input file.");

    /* Добавим аутентификационный жетон в контекст шифра.
     * 
     * int EVP_CIPHER_CTX_get_params(EVP_CIPHER_CTX *ctx, OSSL_PARAM params[]);
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
    if (EVP_CIPHER_CTX_set_params(ctx, params) != 1) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "Could not set authentivation tag.");
    }

    /* Финализируем расшифрование данных.
     *
     * int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
     *
     * EVP_EncryptFinal(), EVP_DecryptFinal() and EVP_CipherFinal()
     * Identical to EVP_EncryptFinal_ex(), EVP_DecryptFinal_ex() and
     * EVP_CipherFinal_ex(). In previous releases they also cleaned up the
     * ctx, but this is no longer done.
     *
     * EVP_DecryptFinal() return 1 for success and 0 for failure.
     */
    int nbytes = 0;
    if (EVP_DecryptFinal(ctx, obuf, &nbytes) != 1) {
        ERR_print_errors_fp(stderr);
        egoto(E0, "Could not finalize decryption.");
    }

    fwrite(obuf, 1, nbytes, ofp);
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
