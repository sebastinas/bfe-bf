#ifndef BFE_BF_MACROS_H
#define BFE_BF_MACORS_H

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#define BFE_BF_GNUC_CHECK(maj, min)                                                                \
  (((__GNUC__ << 20) + (__GNUC_MINOR__ << 10)) >= (((maj) << 20) + ((min) << 10)))
#else
#define BFE_BF_GNUC_CHECK(maj, min) 0
#endif

#ifndef BFE_BF_VISIBLE
#if BFE_BF_GNUC_CHECK(4, 0) || __has_attribute(visibility)
#define BFE_BF_VISIBLE __attribute__((visibility("default")))
#else
#define BFE_BF_VISIBLE
#endif
#endif

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#endif
