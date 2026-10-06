#ifndef __FOO_H__
#define __FOO_H__
// vi: ts=4:sts=4:sw=4:et:noai:nosi:nu:syn=off

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

/* stringify without expanding x */
#define FOO_STRING(x)           #x  
/* expand x, then stringify */
#define FOO_XSTRING(x)          FOO_STRING(x)

#define FOO_CONCAT(x, y)        x##y
#define FOO_XCONCAT(x, y)       FOO_CONCAT(x, y)
#define AUTONAME                FOO_XCONCAT(autoname_, __COUNTER__)

/* Round x up to the nearest multiple of y */
#define roundup_(x, y, y_)      ({ __auto_type y_ = (y); (((x) + (y_ - 1)) / y_) * y_; })
#define roundup(x, y)           roundup_(x, y, AUTONAME)

/* Round x up to a multiple of y, where y is a power of two */
#define roundup2_(x, y, y_)     ({ __auto_type y_ = (y) - 1; ((x) + y_) & ~y_; })
#define roundup2(x, y)          roundup2_(x, y, AUTONAME)

#define log_printf(fmt, ...)    fprintf(stderr, fmt, ##__VA_ARGS__)
#define log_(fmt, ...)          log_printf("%s(),%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

#define log(fmt, ...)           log_(fmt, ##__VA_ARGS__)

#define elog(fmt, ...)          log_(fmt, ##__VA_ARGS__)
#define elog2(e, fmt, ...)      elog(fmt ": %s (errno: %d).", ##__VA_ARGS__, strerror(e), e)

#define egoto(L, fmt, ...)      do { elog(fmt, ##__VA_ARGS__); goto L; } while (0) 
#define egoto2(L, e, fmt, ...)  do { elog2(e, fmt, ##__VA_ARGS__); goto L; } while (0) 

#define eret(code, fmt, ...)    do { elog(fmt, ##__VA_ARGS__); return (code); } while (0) 

#define eret2_(code, e, e_, fmt, ...) \
    do { elog2(e_, fmt, ##__VA_ARGS__); return (code); } while (0) 
#define eret2(code, e, fmt, ...) \
    eret2_(code, e, AUTONAME, fmt, ##__VA_ARGS__)


#define ossl_elog_(e_, file_, line_, func_, data_, flags_, libname_, reason_, fmt, ...) \
    do { \
        unsigned long e_; \
        char const *libname_, *reason_, *file_, *data_, *func_; \
        int line_, flags_, lib_id_, reason_id_, fatal_; \
        \
        e_ = ERR_get_error_all(&file_, &line_, &func_, &data_, &flags_); \
        if (!e_) \
            break; \
        libname_ = ERR_lib_error_string(e_); \
        reason_ = ERR_reason_error_string(e_); \
        lib_id_ = ERR_GET_LIB(e_); \
        reason_id_ = ERR_GET_REASON(e_); \
        fatal_ = ERR_FATAL_ERROR(e_); \
        if (flags_ & ERR_TXT_STRING) \
            elog(fmt ": %s:%d: %s(): err=0x%lx (lib=0x%x, reason=0x%x, fatal=%d), libname=\"%s\", reason=\"%s\", data=\"%s\"", \
                ##__VA_ARGS__, file_, line_, func_, e_, lib_id_, reason_id_, fatal_, libname_, reason_, data_); \
        else \
            elog(fmt ": %s:%d: %s(): err=0x%lx (lib=0x%x, reason=0x%x, fatal=%d), libname=%s, reason=%s", \
                ##__VA_ARGS__, file_, line_, func_, e_, lib_id_, reason_id_, fatal_, libname_, reason_); \
    } while (1)
#define ossl_elog(fmt, ...)         ossl_elog_(AUTONAME, AUTONAME, AUTONAME, AUTONAME, AUTONAME, AUTONAME, AUTONAME, AUTONAME, fmt, ##__VA_ARGS__)

#define ossl_egoto(L, fmt, ...)     do { ossl_elog(fmt, ##__VA_ARGS__); goto L; } while (0)
#define ossl_eret(code, fmt, ...)   do { ossl_elog(fmt, ##__VA_ARGS__); return (code); } while (0) 

#endif
