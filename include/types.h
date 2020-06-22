/*
 *  This file is part of the BFE-BF library.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the CC0 license, see LICENSE for more details.
 *  SPDX-License-Identifier: CC0-1.0
 */

#ifndef BFE_BF_TYPES_H
#define BFE_BF_TYPES_H

#include <stdint.h>

#include <relic/relic.h>

typedef struct {
  uint64_t* bits;
  unsigned int size;
} bitset_t;

typedef struct _bloomfilter_t {
  unsigned int hash_count;
  bitset_t bitset;
} bloomfilter_t;

#endif
