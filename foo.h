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

#define log_(errno_, msgfmt, ...) \
    do { \
        int errno_ = errno; \
        fprintf(stderr, "%s(),%d: " msgfmt "\n", \
            __func__, __LINE__, ##__VA_ARGS__); \
        errno = errno_; \
    } while (0) 

#define log(msgfmt, ...) \
    log_(AUTONAME, msgfmt, ##__VA_ARGS__)

#define elog(msgfmt, ...) \
    log_(AUTONAME, msgfmt, ##__VA_ARGS__)
#define elog2(e, msgfmt, ...) \
    log_(AUTONAME, msgfmt ": %s (errno: %d).", \
        ##__VA_ARGS__, strerror(e), e)

#define egoto(L, msgfmt, ...) \
    do { elog(msgfmt, ##__VA_ARGS__); goto L; } while (0) 
#define egoto2(L, e, msgfmt, ...) \
    do { elog2(e, msgfmt, ##__VA_ARGS__); goto L; } while (0) 

#define eret(code, msgfmt, ...) \
    do { elog(msgfmt, ##__VA_ARGS__); return (code); } while (0) 
#define eret2_(code, e, e_, msgfmt, ...) \
    do { \
        int e_ = (e); \
        elog2(e_, msgfmt, ##__VA_ARGS__); \
        errno = e_; \
        return (code); \
    } while (0) 
#define eret2(code, e, msgfmt, ...) \
    eret2_(code, e, AUTONAME, msgfmt, ##__VA_ARGS__)

#endif
