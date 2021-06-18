/*
 *  This file is part of the BFE library.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the CC0 license, see LICENSE for more details.
 *  SPDX-License-Identifier: CC0-1.0
 */

#ifndef BFE_MACROS_H
#define BFE_MACROS_H

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#define BFE_GNUC_CHECK(maj, min)                                                                   \
  (((__GNUC__ << 20) + (__GNUC_MINOR__ << 10)) >= (((maj) << 20) + ((min) << 10)))
#else
#define BFE_GNUC_CHECK(maj, min) 0
#endif

#ifndef BFE_VISIBLE
#if BFE_GNUC_CHECK(4, 0) || __has_attribute(visibility)
#define BFE_VISIBLE __attribute__((visibility("default")))
#else
#define BFE_VISIBLE
#endif
#endif

#endif
