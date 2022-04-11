/*
 *  This file is part of the BFE library.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the CC0 license, see LICENSE for more details.
 *  SPDX-License-Identifier: CC0-1.0
 */

#ifndef BFE_BFE_BF_H
#define BFE_BFE_BF_H

/**
 * @mainpage
 *
 * The BFE library implements an IND-CCA secure puncturable key encapsulation mechanism from
 * bloom filter encryption basedon the Boneh-Franklin IBE.
 *
 * In the following, we present the typical usage of the library including key generation,
 * encapsualtion, decapusalation, and puncturing. The examples also examplify the serialization and
 * deserialization of the structures to the byte arrays.
 *
 * Let's start with key generation:
 * @code{.c}
 *  bfe_bf_secret_key_t sk;
 *  bfe_bf_public_key_t pk;
 *
 *  // generate new keys
 *  bfe_bf_init_secret_key(&sk);
 *  bfe_bf_init_public_key(&pk);
 *  if (bfe_bf_keygen(&pk, &sk, 32, 1 << 19, 0.0009765625)) {
 *    // handle error
 *  }
 *
 *  // serialize public key
 *  uint8_t serialized_pk[bfe_bf_public_key_size()];
 *  bfe_bf_public_key_serialize(serialized_pk, &pk);
 *
 *  // serialize secret key
 *  uint8_t* serialized_sk = malloc(bfe_bf_secret_key_size(&sk));
 *  bfe_bf_secret_key_serialize(serialized_sk, &sk);
 *
 *  // clean up keys
 *  bfe_bf_clear_secret_key(&sk);
 *  bfe_bf_clear_public_key(&pk);
 * @endcode
 * The paramters passed to @ref bfe_bf_keygen setups the system to encapsulate 32 byte keys with a
 * bloom filter size of <code>2^19</code> elements and a correctness error of approximately
 * <code>2^-10</code>.
 *
 * We note that the public key is small enough to fit on the stack. The secret key, however, needs
 * to be serialized directly to a memory mapped file or large enough array on the heap.
 *
 * The following code examplifies encapsulation:
 * @code{.c}
 *  // the serialized public key
 *  const uint8_t* serialized_pk;
 *  bfe_bf_public_key_t pk;
 *
 *  // deserialize the public key
 *  if (bfe_bf_public_key_deserialize(&pk, serialized_pk)) {
 *    // handle error
 *  }
 *
 *  // encaps a new key
 *  bfe_bf_ciphertext_t ciphertext;
 *  bfe_bf_init_ciphertext(&ciphertext, &pk);
 *  uint8_t key[pk.key_size];
 *  if (bfe_bf_encaps(&ciphertext, K, &pk)) {
 *    // handle error
 *  }
 *
 *  // serialize the ciphertext
 *  const size_t csize = bfe_bf_ciphertext_size(&ciphertext);
 *  uint8_t serialized_ct[csize];
 *  bfe_bf_ciphertext_serialize(serialized_ct, &ciphertext);
 *
 *  // clean up
 *  bfe_bf_clear_ciphertext(&ciphertext);
 *  bfe_bf_clear_public_key(&pk);
 * @endcode
 * and decapsulation with puncturing:
 * @code{.c}
 *  // the serialized secret key
 *  uint8_t* serialized_sk;
 *  // the serialized public key
 *  const uint8_t* public_key
 *  // the serialized ciphertext
 *  const uint8_t* serialized_ct;
 *
 *  // deserialize the secret key
 *  bfe_bf_secret_key_t sk;
 *  if (bfe_bf_secret_key_deserialize(&sk, serialized_sk)) {
 *    // handle error
 *  }
 *
 *  // deserialize the public key
 *  bfe_bf_public_key_t pk;
 *  if (bfe_bf_public_key_deserialize(&pk, serialized_pk)) {
 *    // handle error
 *  }
 *
 *  // deserialize the ciphertext
 *  bfe_bf_ciphertext_t ciphertext;
 *  if (bfe_bf_ciphertext_deserialize(&ciphertext, serialized_ct)) {
 *    // handle error
 *  }
 *
 *  // decaps ciphertext
 *  uint8_t key[pk.key_size];
 *  if (bfe_bf_decaps(key, &pk, &sk, &ciphertext)) {
 *    // handle error
 *  }
 *
 *  // puncture secret key and serialized it again
 *  bfe_bf_puncture(&sk, &ciphertext);
 *  bfe_bf_secret_key_serialize(seralized_sk, &sk);
 *
 *  // clean up
 *  bfe_bf_clear_ciphertext(&ciphertext);
 *  bfe_bf_clear_public_key(&pk);
 *  bfe_bf_clear_secret_key(&sk);
 * @endcode
 *
 * The library also privides a KEM API as defined for the NIST Post-Quantum Cryptography project.
 * Again, let's start with encryption:
 * @code{.c}
 *  // the public key
 *  unsigned char pk[CRYPTO_PUBLICKEYBYTES];
 *  // the secret key
 *  unsigned char* sk = malloc(CRYPTO_SECRETKEYBYTES);
 *
 *  // generate key pair
 *  if (crypto_kem_keypair(pk, sk)) {
 *    // handle error
 *  }
 * @endcode
 *
 * Encapsulation:
 * @code{.c}
 *  // the public key
 *  unsigned char* pk;
 *
 *  // the ciphertext
 *  unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
 *  // encapsulate a new key
 *  unsigned char k[CRYPTO_BYTES];
 *  if (crypto_kem_enc(ct, k, pk)) {
 *    // handle error
 *  }
 * @endcode
 *
 * Decapsulation:
 * @code{.c}
 *  // the secret key
 *  unsigned char* sk;
 *  // the cipher text
 *  unsigned char* ct;
 *
 *  // decapsulate key
 *  unsigned char k[CRYPTO_BYTES];
 *  if (crypto_kem_dec(k, ct, sk)) {
 *    // handle error
 *  }
 * @endcode
 *
 * Puncturing:
 * @code{.c}
 *  // the secret key
 *  unsigned char* sk;
 *  // the cipher text
 *  unsigned char* ct;
 *
 *  // puncture secret key with respect to a ciphertext
 *  if (crypto_kem_punc(sk, ct)) {
 *    // handle error
 *  }
 * @endcode
 */

#include "macros.h"
#include "types.h"

#include <stdint.h>

BFE_BEGIN_CDECL

/**
 * BFE PKEM public key
 */
typedef struct {
  unsigned int filter_hash_count; /**< number of hash functions used in the bloom filter */
  unsigned int filter_size;       /**< size of the bloom filter */
  unsigned int key_size;          /**< size of encapuslated keys */

  ep_t public_key; /**< the public key of the Boneh-Franklin IBE */
} bfe_bf_public_key_t;

/**
 * BFE PKEM secret key
 */
typedef struct {
  bloomfilter_t filter;         /**< the bloom filter */
  unsigned int secret_keys_len; /**< size of @ref secret_keys */
  ep2_t* secret_keys;           /**< all available secret keys */
} bfe_bf_secret_key_t;

/**
 * BFE PKEM ciphertext
 */
typedef struct {
  ep_t u;
  unsigned int v_size;
  uint8_t* v;
} bfe_bf_ciphertext_t;

/**
 * Initialize secret key.
 *
 * @param[out] secret_key the secret key
 * @return BFE_SUCCESS or an error code on failure
 */
BFE_VISIBLE int bfe_bf_init_secret_key(bfe_bf_secret_key_t* secret_key);
/**
 * Clear secret key.
 *
 * @param[out] secret_key the secret key
 */
BFE_VISIBLE void bfe_bf_clear_secret_key(bfe_bf_secret_key_t* secret_key);

/**
 * Initialize public key.
 *
 * @param[out] public_key the public key
 * @return BFE_SUCCESS or an error code on failure
 */
BFE_VISIBLE int bfe_bf_init_public_key(bfe_bf_public_key_t* public_key);
/**
 * Clear public key.
 *
 * @param[out] public_key the public key
 */
BFE_VISIBLE void bfe_bf_clear_public_key(bfe_bf_public_key_t* public_key);

/**
 * Sets up the Bloom Filter Encryption (bfe) scheme and create public and secret keys.
 *
 * @param[out] public_key the public key
 * @param[out] secret_key the secret key
 * @param[in] key_length length of the encapsulated keys
 * @param[in] filter_element_number desired number of elements in the bloom filter
 * @param[in] false_positive_probability desired false positive probability of the bloom filter
 * @return BFE_SUCCESS or an error code on failure.
 */
BFE_VISIBLE int bfe_bf_keygen(bfe_bf_public_key_t* public_key, bfe_bf_secret_key_t* secret_key,
                              unsigned int key_length, unsigned int filter_element_number,
                              double false_positive_probability);

/**
 * Generates a random key K and encapsulates it.
 *
 * @param[out] ciphertext the ciphertext
 * @param[out] K the randomly generated key
 * @param[in] public_key the public key
 * @return BFE_SUCCESS or an error code on failure.
 */
BFE_VISIBLE int bfe_bf_encaps(bfe_bf_ciphertext_t* ciphertext, uint8_t* K,
                              const bfe_bf_public_key_t* public_key);

/**
 * Punctures a secret key for the given ciphertext. After this action the secret key will not be
 * usable for decrypting the same ciphertext again. This function runs in place which means a passed
 * secret key will be modified.
 *
 * @param[out] secret_key the secret key to be punctured
 * @param[in] ciphertext ciphertext for which the secret key is being punctured
 */
BFE_VISIBLE void bfe_bf_puncture(bfe_bf_secret_key_t* secret_key, bfe_bf_ciphertext_t* ciphertext);

/**
 * Decapsulates a given ciphertext. The secret key should not be already punctured with the same
 * ciphertext.
 *
 * @param[out] key the returned decrypted key
 * @param[in] public_key the public key
 * @param[in] secret_key the secret key to be used for decrypting
 * @param[in] ciphertext the ciphertext
 * @return BFE_SUCCESS or an error code on failure.
 */
BFE_VISIBLE int bfe_bf_decaps(uint8_t* key, const bfe_bf_public_key_t* public_key,
                              const bfe_bf_secret_key_t* secret_key,
                              bfe_bf_ciphertext_t* ciphertext);

/**
 * Init the ciphertext.
 *
 * @param[out] ciphertext the ciphertext
 * @param[in] public_key the pulic key
 * @return BFE_SUCCESS or an error code on failure.
 */
BFE_VISIBLE int bfe_bf_init_ciphertext(bfe_bf_ciphertext_t* ciphertext,
                                       const bfe_bf_public_key_t* public_key);
/**
 * Clear the ciphertext.
 *
 * @param[out] ciphertext the ciphertext
 */
BFE_VISIBLE void bfe_bf_clear_ciphertext(bfe_bf_ciphertext_t* ciphertext);

/**
 * Calculates number of bytes needed to store a given ciphertext.
 *
 * @param[in] ciphertext the ciphertext.
 * @return Number of bytes needed to store the ciphertext.
 */
BFE_VISIBLE unsigned int bfe_bf_ciphertext_size(const bfe_bf_ciphertext_t* ciphertext);

/**
 * Writes a given ciphertext to a byte array.
 *
 * @param[out] bin the ciphertext byte array.
 * @param[in] ciphertext the ciphertext.
 */
BFE_VISIBLE void bfe_bf_ciphertext_serialize(uint8_t* bin, const bfe_bf_ciphertext_t* ciphertext);

/**
 * Reads a given ciphertext stored as a byte array.
 *
 * @param[out] ciphertext the ciphertext
 * @param[in] bin the destination byte array.
 * @return BFE_SUCCESS or an error code on failure.
 */
BFE_VISIBLE int bfe_bf_ciphertext_deserialize(bfe_bf_ciphertext_t* ciphertext, const uint8_t* bin);

/**
 * Calculates number of bytes needed to store a given secret key.
 *
 * @param[in] secret_key the secret key.
 * @return Number of bytes needed to store the secret key.
 */
BFE_VISIBLE unsigned int bfe_bf_secret_key_size(const bfe_bf_secret_key_t* secret_key);

/**
 * Writes a given secret key to a byte array.
 *
 * @param[out] bin the secret key byte array.
 * @param[in] secret_key the secret key.
 */
BFE_VISIBLE void bfe_bf_secret_key_serialize(uint8_t* bin, const bfe_bf_secret_key_t* secret_key);

/**
 * Reads a given secret key stored as a byte array.
 *
 * @param[out] secret_key the secret key
 * @param[in] bin the destination byte array.
 * @return BFE_SUCCESS or an error code on failure.
 */
BFE_VISIBLE int bfe_bf_secret_key_deserialize(bfe_bf_secret_key_t* secret_key, const uint8_t* bin);

/**
 * Calculates number of bytes needed to store a given public key.
 *
 * @return Number of bytes needed to store the public key.
 */
BFE_VISIBLE unsigned int bfe_bf_public_key_size(void);

/**
 * Writes a given public key to a byte array.
 *
 * @param[out] bin the public key byte array.
 * @param[in] public_key the public key.
 */
BFE_VISIBLE void bfe_bf_public_key_serialize(uint8_t* bin, const bfe_bf_public_key_t* public_key);

/**
 * Reads a given public key stored as a byte array.
 *
 * @param[out] public_key the public key
 * @param[in] bin the destination byte array.
 * @return BFE_SUCCESS or an error code on failure.
 */
BFE_VISIBLE int bfe_bf_public_key_deserialize(bfe_bf_public_key_t* public_key, const uint8_t* bin);

BFE_END_CDECL

#endif // BFE_BFE_BE_H
