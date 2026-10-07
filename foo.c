// vi: ts=4:sts=4:sw=4:et:nu:noai:nosi:syn=off

#include <openssl/err.h>
#include "foo.h"

static __thread char *pos;
static __thread size_t cap, len;
static __thread char buf[0x1000];

static void log_bprefix_default(char const *file, int line, char const *func);
__thread log_bprefix_t log_bprefix = log_bprefix_default;

void log_breset() {
    pos = buf;
    cap = sizeof buf - 1;
    len = 0;
    buf[0] = '\0';
}

void log_bvprintf(char const *fmt, va_list ap) {
    size_t n = vsnprintf(pos, cap, fmt, ap);
    if (n > cap)
        n = cap;
    pos += n;
    cap -= n;
    len += n;
    *pos = '\0';
}

void log_bprintf(char const *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_bvprintf(fmt, ap);
    va_end(ap);
}

void log_bprefix_default(char const *file, int line, char const *func) {
    log_bprintf("%s:%d: %s()", file, line, func);
}

void log_flush() {
    fflush(stdout);
    fprintf(stderr, "%s\n", buf);
    log_breset();
}

void vlog_ex(
    char const *file, int line, char const *func,
    char const *fmt, va_list ap)
{
    log_breset();
    log_bprefix(file, line, func);
    log_bprintf(": ");
    log_bvprintf(fmt, ap);
    log_flush();
}

void log_ex(
    char const *file, int line, char const *func,
    char const *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vlog_ex(file, line, func, fmt, ap);
    va_end(ap);
}

void ossl_velog_ex(
    char const *file, int line, char const *func,
    char const *fmt, va_list ap)
{
    unsigned long e_;
    char const *libname_, *reason_, *file_, *data_, *func_;
    int line_, flags_, lib_id_, reason_id_, fatal_;

    e_ = ERR_get_error_all(&file_, &line_, &func_, &data_, &flags_);
    if (e_) {
        libname_ = ERR_lib_error_string(e_);
        reason_ = ERR_reason_error_string(e_);
        lib_id_ = ERR_GET_LIB(e_);
        reason_id_ = ERR_GET_REASON(e_);
        fatal_ = ERR_FATAL_ERROR(e_);

        log_breset();
        log_bprefix(file, line, func);
        log_bprintf(": ");
        log_bvprintf(fmt, ap);
        log_bprintf(
            ": %s:%d: %s(): err=0x%lx (lib=0x%x, reason=0x%x, fatal=%d),"
            " libname=\"%s\", reason=\"%s\"",
            file_, line_, func_, e_, lib_id_, reason_id_,
            fatal_, libname_, reason_
        );
        if (flags_ & ERR_TXT_STRING)
            log_bprintf(", data=\"%s\".", data_);
        log_flush();
    }
}

void ossl_elog_ex(
    char const *file, int line, char const *func,
    char const *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    ossl_velog_ex(file, line, func, fmt, ap);
    va_end(ap);
}
