#ifndef BLOOM_H
#define BLOOM_H

#include "FIPS202-opt64/KeccakHash.h"
#include "include/types.h"

#include <math.h>
#include <stdint.h>

/* bitset implementation */

#define BITSET_WORD_BITS (8 * sizeof(uint64_t))
#define BITSET_SIZE(size) (((size) + BITSET_WORD_BITS - 1) / BITSET_WORD_BITS)

/**
 * Creates a bitset with the given number of bits.
 *
 * @param size the number of bits.
 * @return The initialized bitset with all bits set to 0.
 */
static inline bitset_t bitset_init(unsigned int size) {
  return (bitset_t){.bits = calloc(BITSET_SIZE(size), sizeof(uint64_t)), .size = size};
}

/**
 * Sets a specific bit of a bitset.
 *
 * @param bitset the bitset.
 * @param index  the index of the bit supposed to be set to 1.
 */
static inline void bitset_set(bitset_t* bitset, unsigned int index) {
  bitset->bits[index / BITSET_WORD_BITS] |= (UINT64_C(1) << (index & (BITSET_WORD_BITS - 1)));
}

/**
 * Retrieves a specific bit of a bitset.
 *
 * @param bitset the bitset.
 * @param index  the index of the bit in question.
 * @return non-0 if the bit is set, 0 otherwise
 */
static inline uint64_t bitset_get(const bitset_t* bitset, unsigned int index) {
  return bitset->bits[index / BITSET_WORD_BITS] & (UINT64_C(1) << (index & (BITSET_WORD_BITS - 1)));
}

/**
 * Computes the number of set bits of a bitset.
 *
 * @param bitset the bitset.
 * @return number of set bits
 */
static inline unsigned int bitset_popcount(const bitset_t* bitset) {
  unsigned int bits = 0;
  for (unsigned int idx = 0; idx != BITSET_SIZE(bitset->size); ++idx) {
    bits += __builtin_popcount(bitset->bits[idx]);
  }
  return bits;
}

/**
 * Frees the memory allocated by the bitset.
 *
 * @param bitset the bitset.
 */
static inline void bitset_clean(bitset_t* bitset) {
  if (bitset) {
    free(bitset->bits);
    bitset->bits = NULL;
    bitset->size = 0;
  }
}

/* bloom filter implementation */
static inline unsigned int bf_get_needed_size(unsigned int n, double false_positive_prob) {
  return -floor((n * log(false_positive_prob)) / (log(2) * log(2)));
}

static inline bloomfilter_t bf_init_fixed(unsigned int size, unsigned int hash_count) {
  return (bloomfilter_t){.hash_count = hash_count, .bitset = bitset_init(size)};
}

static inline bloomfilter_t bf_init(unsigned int n, double false_positive_prob) {
  const unsigned int bitset_size = bf_get_needed_size(n, false_positive_prob);

  return (bloomfilter_t){.hash_count = ceil((bitset_size / (double)n) * log(2)),
                         .bitset     = bitset_init(bitset_size)};
}

static inline unsigned int bf_get_position(uint32_t hash_idx, const uint8_t* input,
                                           size_t input_len, unsigned int filter_size) {
  static const uint8_t domain[] = "BF_HASH";

  Keccak_HashInstance shake;
  Keccak_HashInitialize_SHAKE128(&shake);

  Keccak_HashUpdate(&shake, domain, sizeof(domain) * 8);
  hash_idx = htole32(hash_idx);
  Keccak_HashUpdate(&shake, (const uint8_t*)&hash_idx, sizeof(hash_idx) * 8);
  Keccak_HashUpdate(&shake, input, input_len * 8);
  Keccak_HashFinal(&shake, NULL);

  uint64_t output = 0;
  Keccak_HashSqueeze(&shake, (uint8_t*)&output, sizeof(output) * 8);
  return le64toh(output) % filter_size;
}

/**
 * Reset all bits of the bloom filter
 *
 * @param reset the bloom filter
 */
static inline void bf_reset(bloomfilter_t* filter) {
  memset(filter->bitset.bits, 0, BITSET_SIZE(filter->bitset.size) * sizeof(uint64_t));
}

static inline void bf_clear(bloomfilter_t* filter) {
  if (filter) {
    bitset_clean(&filter->bitset);
  }
}

#endif
