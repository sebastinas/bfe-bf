#ifndef BFE_TBFE_BBG_TOOLSH
#define BFE_TBFE_BBG_TOOLSH

#include <stdbool.h>

#include "include/tbfe-bbg.h"

/**
 * Checks if the given public keys are equal.
 *
 * @param[in] l     - the first public key
 * @param[in] r     - the second public key
 *
 * @return True if the public keys are equal, false otherwise.
 */
bool tbfe_bbg_public_keys_are_equal(tbfe_bbg_public_key_t* l, tbfe_bbg_public_key_t* r);

/**
 * Checks if the given secret keys are equal.
 *
 * @param[in] l     - the first secret key
 * @param[in] r     - the second secret key
 *
 * @return True if the secret keys are equal, false otherwise.
 */
bool tbfe_bbg_secret_keys_are_equal(tbfe_bbg_secret_key_t* l, tbfe_bbg_secret_key_t* r);

/**
 * Checks if the given ciphertexts are equal.
 *
 * @param[in] l     - the first ciphertext
 * @param[in] r     - the second ciphertext
 *
 * @return True if the ciphertexts are equal, false otherwise.
 */
bool tbfe_bbg_ciphertexts_are_equal(tbfe_bbg_ciphertext_t* l, tbfe_bbg_ciphertext_t* r);

#endif
