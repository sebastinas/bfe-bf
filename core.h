#ifndef CORE_H
#define CORE_H

#include <relic/relic.h>

#include "FIPS202-opt64/KeccakHash.h"

/* not exactly true, but large enough */
#define MAX_ORDER_SIZE RLC_FP_BYTES

extern unsigned int order_size;

/**
 * Sample a random element from Z_p^*
 */
void zp_rand(bn_t b);

/**
 * Adds two elements from Z_p.
 *
 * @param[out] c            - the resulting element
 * @param[in] a             - the first input element
 * @param[in] b             - the second input element
 */
void zp_add(bn_t c, const bn_t a, const bn_t b);

/**
 * Substracts two elements from Z_p.
 *
 * @param[out] c            - the resulting element
 * @param[in] a             - the first input element
 * @param[in] b             - the second input element
 */
void zp_sub(bn_t c, const bn_t a, const bn_t b);

/**
 * Multiplies two elements from Z_p.
 *
 * @param[out] c            - the resulting element
 * @param[in] a             - the first input element
 * @param[in] b             - the second input element
 *
 * @return BFE_SUCCESS if no error occurs, an error code otherwise.
 */
void zp_mul(bn_t c, const bn_t a, const bn_t b);

/**
 * Divides two elements from Z_p.
 *
 * @param[out] c            - the resulting element
 * @param[in] a             - the first input element
 * @param[in] b             - the second input element
 */
void zp_div(bn_t c, const bn_t a, const bn_t b);

/**
 * Squeezes a Z_p^* from the SHAKE instance by interpreting the hash
 * value as binary coded number which is then reduced by the group order.
 */
void hash_squeeze_zp(bn_t bn, Keccak_HashInstance* ctx);

#endif
