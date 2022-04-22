/*
 *  This file is part of the BFE library.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the CC0 license, see LICENSE for more details.
 *  SPDX-License-Identifier: CC0-1.0
 */

#ifndef BFE_TBFE_BBG_H
#define BFE_TBFE_BBG_H

#include "macros.h"
#include "types.h"

BFE_BEGIN_CDECL

/**
 * Initialize a public key.
 *
 * @param[out] public_key - public key to initialize
 * @param[in] total_depth - maximal depth
 *
 * @return BFE_SUCCESS if no error occurs, an error code otherwise.
 */
BFE_VISIBLE int tbfe_bbg_init_public_key(tbfe_bbg_public_key_t* public_key,
                                         unsigned int total_depth);
/**
 * Deserialize public key
 *
 * @param[out] public_key - public key to initialize
 * @param[in] src - serialized public key
 *
 * @return BFE_SUCCESS if no error occurs, an error code otherwise.
 */
BFE_VISIBLE int tbfe_bbg_init_public_key_from_serialized(tbfe_bbg_public_key_t* public_key,
                                                         const uint8_t* src);
/**
 * Clear a public key.
 *
 * @param[out] public_key - public key to clear
 */
BFE_VISIBLE void tbfe_bbg_clear_public_key(tbfe_bbg_public_key_t* public_key);

/**
 * Initialize a secret key.
 *
 * @param[out] secret_key - secret key to initialize
 * @param[in] bloom_filter_size - size of the bloom filter
 * @param[in] false_positive_prob - false-positive probability of the bloom filter
 *
 * @return BFE_SUCCESS if nor error occurs, an error code otherwise.
 */
BFE_VISIBLE int tbfe_bbg_init_secret_key(tbfe_bbg_secret_key_t* secret_key,
                                         unsigned int bloom_filter_size,
                                         double false_positive_prob);

/**
 * Deserialize secret key
 *
 * @param[out] secret_key - secret key to inialize
 * @param[in] src - serialized public key
 *
 * @return BFE_SUCCESS if no error occurs, an error code otherwise.
 */
BFE_VISIBLE int tbfe_bbg_init_secret_key_from_serialized(tbfe_bbg_secret_key_t* secret_key,
                                                         const uint8_t* src);
/*
 * Clear a secret key.
 *
 * @param[out] secret_key - secret key to clear
 */
BFE_VISIBLE void tbfe_bbg_clear_secret_key(tbfe_bbg_secret_key_t* secret_key);

/**
 * Initialize ciphertext.
 *
 * @param[out] ciphertext - ciphertext to intialize
 *
 * @return BFE_SUCCESS if no error occurs, an error code otherwise.
 */
BFE_VISIBLE int tbfe_bbg_init_ciphertext(tbfe_bbg_ciphertext_t* ciphertext);
/**
 * Deserialize ciphertext.
 *
 * @param[out] ciphertext - ciphertext to initialize
 * @param[in] src - serialized secret key
 *
 * @return BFE_SUCCESS if no error occurs, an error code otherwise.
 */
BFE_VISIBLE int tbfe_bbg_init_ciphertext_from_serialized(tbfe_bbg_ciphertext_t* ciphertext,
                                                         const uint8_t* src);
/**
 * Clear a ciphertext
 *
 * @param[out] ciphertext - ciphertext to clear
 */
BFE_VISIBLE void tbfe_bbg_clear_ciphertext(tbfe_bbg_ciphertext_t* ciphertext);

/**
 * Generates a new key pair of public and secret key.
 *
 * @param[out] public_key               - the newly generated public key
 * @param[out] secret_key               - the newly generated secret key
 *
 * @return BFE_SUCCESS if no error occurs, an error code otherwise.
 */
BFE_VISIBLE int tbfe_bbg_keygen(tbfe_bbg_public_key_t* public_key,
                                tbfe_bbg_secret_key_t* secret_key);

/**
 * Generates a new session key and outputs it together with an encapsulation of the key under the
 * given public key.
 *
 * @param[out] key              - the newly generated session key
 * @param[out] ciphertext       - the ciphertext encapsulating the new session key
 * @param[in] public_key        - the public key under which the ciphertext is encapsulated
 * @param[in] time_interval     - the time slot identifer
 *
 * @return BFE_SUCCESS if no error occurs, an error code otherwise.
 */
BFE_VISIBLE int tbfe_bbg_encaps(uint8_t* key, tbfe_bbg_ciphertext_t* ciphertext,
                                tbfe_bbg_public_key_t* public_key, unsigned int time_interval);

/**
 * Decapuslates the given ciphertext with the given secret and public key and outputs the resulting
 * session key. If all secret key for the given ciphertext are deleted key is NULL.
 *
 * @param[out] key              - the decapsulated session key (can be NULL)
 * @param[in] ciphertext        - the ciphertext which is decapuslated
 * @param[in] secret_key        - the secret key with which the ciphertext is decapsulated
 * @param[in] public_key        - the public key with which the ciphertext is decapsulated
 *
 * @return BFE_SUCCESS if no error occurs, an error code otherwise.
 */
BFE_VISIBLE int tbfe_bbg_decaps(uint8_t* key, tbfe_bbg_ciphertext_t* ciphertext,
                                tbfe_bbg_secret_key_t* secret_key,
                                tbfe_bbg_public_key_t* public_key);

/**
 * Punctures the given secret key for the given ciphertext.
 *
 * @param[in,out] secret_key        - the secret key that is punctured for the given ciphertext
 * @param[in] ciphertext            - the ciphertext for which the given secret key is punctured
 *
 * @return BFE_SUCCESS if no error occurs, an error code otherwise.
 */
BFE_VISIBLE int tbfe_bbg_puncture_ciphertext(tbfe_bbg_secret_key_t* secret_key,
                                             tbfe_bbg_ciphertext_t* ciphertext);

/**
 * Punctures the given secret key for the given time interval.
 *
 * @param[in,out] secret_key        - the secret key that is punctured for the given ciphertext
 * @param[in] public_key            - the public key
 * @param[in] time_interval         - the time inverval for which the given secret key is punctured
 *
 * @return BFE_SUCCESS if no error occurs, an error code otherwise.
 */
BFE_VISIBLE int tbfe_bbg_puncture_interval(tbfe_bbg_secret_key_t* secret_key,
                                           tbfe_bbg_public_key_t* public_key,
                                           unsigned int time_interval);

/**
 * Serializes the given public key.
 *
 * @param[out] serialized       - the serialized public key
 * @param[in] public_key        - the public key that is serialized
 */
BFE_VISIBLE void tbfe_bbg_serialize_public_key(uint8_t* serialized,
                                               tbfe_bbg_public_key_t* public_key);

/**
 * Serializes the given secret key.
 *
 * @param[out] serialized       - the serialized secret key
 * @param[in] secret_key        - the secret key that is serialized
 */
BFE_VISIBLE void tbfe_bbg_serialize_secret_key(uint8_t* serialized,
                                               tbfe_bbg_secret_key_t* secret_key);

/**
 * Serializes the given ciphertext.
 *
 * @param[out] serialized       - the serialized ciphertext
 * @param[in] ciphertext        - the ciphertext that is serialized
 */
BFE_VISIBLE void tbfe_bbg_serialize_ciphertext(uint8_t* serialized,
                                               tbfe_bbg_ciphertext_t* ciphertext);

/**
 * Returns the size of the given public key.
 *
 * @param[in] public_key        - the public key whose size to return
 *
 * @return the size of the public key.
 */
BFE_VISIBLE unsigned tbfe_bbg_get_public_key_size(const tbfe_bbg_public_key_t* public_key);

/**
 * Returns the size of the given secret key.
 *
 * @param[in] secret_key        - the secret key whose size to return
 *
 * @return the size of the secret key.
 */
BFE_VISIBLE unsigned tbfe_bbg_get_secret_key_size(const tbfe_bbg_secret_key_t* secret_key);

/**
 * Returns the size of the given ciphertext.
 *
 * @param[in] ciphertext        - the ciphertext whose size to return
 *
 * @return the size of the ciphertext.
 */
BFE_VISIBLE unsigned tbfe_bbg_get_ciphertext_size(const tbfe_bbg_ciphertext_t* ciphertext);

BFE_END_CDECL

#endif
