/*
 *  This file is part of the BFE library.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the CC0 license, see LICENSE for more details.
 *  SPDX-License-Identifier: CC0-1.0
 */

#ifndef BFE_TYPES_H
#define BFE_TYPES_H

#include "macros.h"

#include <stdint.h>

#include <omp.h>
#include <relic/relic.h>

#define SECURITY_PARAMETER 32

BFE_BEGIN_CDECL

/* error codes */

typedef enum {
  BFE_SUCCESS             = 0, /**< All operations were successful */
  BFE_ERROR               = 1, /**< An error occurred */
  BFE_ERROR_INVALID_PARAM = 2, /**< An invalid parameter was given */
  BFE_ERROR_KEY_PUNCTURED = 3, /**< The key was already punctured */
} bfe_bf_error_t;

/* bloom filter */

typedef struct {
  uint64_t* bits;
  unsigned int size;
} bitset_t;

typedef struct _bloomfilter_t {
  unsigned int hash_count;
  bitset_t bitset;
} bloomfilter_t;

struct vector;
typedef struct vector vector_t;

/* types for TBFE */

typedef struct {
  gt_t pk;
} bbg_public_key_t;

typedef struct {
  unsigned max_delegatable_depth;
  g1_t g;
  g2_t g_hat;
  g1_t g2;
  g1_t g3;
  g1_t* h;
  g1_t* h_precomputation_tables;
} bbg_public_params_t;

typedef struct {
  g1_t fs;
  g1_t hs;
  g1_t cs;
} bbg_ots_pk_t;

typedef struct {
  bn_t r;
  bn_t s;
} bbg_ots_t;

typedef struct {
  bbg_public_key_t pk;
  bbg_public_params_t params;
  unsigned bloom_filter_size;
  unsigned bloom_filter_hashes;
} tbfe_bbg_public_key_t;

typedef struct {
  bloomfilter_t bloom_filter;
  omp_lock_t bloom_filter_mutex;
  vector_t* sk_bloom;
  vector_t* sk_time;
  unsigned next_interval;
} tbfe_bbg_secret_key_t;

typedef struct {
  uint8_t c[SECURITY_PARAMETER];
  vector_t* Cs;
  bbg_ots_t ots;
  bbg_ots_pk_t ots_pk;
  unsigned int time_interval;
} tbfe_bbg_ciphertext_t;

BFE_END_CDECL

#endif
