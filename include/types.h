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

#include <openssl/evp.h>
#include <openssl/pem.h>

#define SECURITY_PARAMETER 32

// Size of EdDSA keys in bytes (32 bytes -> 256 bits)
#define Ed25519_KEY_BYTES 32
// Size of EdDSA signature in bytes (64 bytes -> 512 bits)
#define Ed25519_SIG_BYTES 64


BFE_BEGIN_CDECL

/* error codes */

typedef enum {
  BFE_SUCCESS             = 0, /**< All operations were successful */
  BFE_ERROR               = 1, /**< An error occurred */
  BFE_ERROR_INVALID_PARAM = 2, /**< An invalid parameter was given */
  BFE_ERROR_KEY_PUNCTURED = 3, /**< The key was already punctured */
} bfe_bf_error_t;

// Error codes for OpenSSL EVP
typedef enum {
  EVP_FAILURE = 0,             /**< An error occurred */
  EVP_SUCCESS = 1,             /**< All operations were successful */
} evp_error_t;


/* bloom filter */

/**
 * A bitset to store the bloomfilter
 *
 * @internal
 */
typedef struct {
  uint64_t* bits;
  unsigned int size;
} bitset_t;

/**
 * A bloom filter
 *
 * @internal
 */
typedef struct {
  unsigned int hash_count;
  bitset_t bitset;
} bloomfilter_t;

struct vector;
typedef struct vector vector_t;

/* types for TBFE */

/**
 * Public key of a BBG HIBE
 *
 * @internal
 */
typedef struct {
  gt_t pk;
} bbg_public_key_t;

/**
 * Public parameters of a BBG HIBE
 *
 * @internal
 */
typedef struct {
  unsigned max_delegatable_depth;
  g1_t g;
  g2_t g_hat;
  g1_t g2;
  g1_t g3;
  g1_t* h;
  g1_t* h_precomputation_tables;
} bbg_public_params_t;

/**
 * EdDSA public key 
 */
typedef struct {
  unsigned char key[Ed25519_KEY_BYTES]; /**< Unsigned byte array containing the RAW public key */
} eddsa_pk_t;

/**
 * EdDSA secret key 
 */
typedef struct {
  unsigned char key[Ed25519_KEY_BYTES]; /**< Unsigned byte array containing the RAW private key */
} eddsa_sk_t;

/**
 * EdDSA Signature
 */
typedef struct {
  unsigned char sig[Ed25519_SIG_BYTES]; /**< Unsigned byte array representing the signature */
} eddsa_sig_t;

/**
 * TB-BFE PKEM public key
 */
typedef struct {
  bbg_public_key_t pk;
  bbg_public_params_t params;
  unsigned bloom_filter_size;
  unsigned bloom_filter_hashes;
} tbfe_bbg_public_key_t;

/**
 * TB-BFE PKEM secret key
 */
typedef struct {
  bloomfilter_t bloom_filter;
  omp_lock_t bloom_filter_mutex;
  vector_t* sk_bloom;
  vector_t* sk_time;
  unsigned next_interval;
} tbfe_bbg_secret_key_t;

/**
 * TB-BFE PKEM ciphertext
 */
typedef struct {
  uint8_t c[SECURITY_PARAMETER];  
  vector_t* Cs;                   
  eddsa_sig_t eddsa;              
  eddsa_pk_t eddsa_pk;            
  unsigned int time_interval;    
} tbfe_bbg_ciphertext_t;



BFE_END_CDECL

#endif
