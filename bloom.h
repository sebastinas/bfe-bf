#ifndef BLOOM_H
#define BLOOM_H

#include "FIPS202-opt64/KeccakHash.h"
#include "include/types.h"
#include "utils.h"

#include <math.h>
#include <stdint.h>

/* bitset implementation */

#define BITSET_WORD_BITS (8 * sizeof(uint64_t))
#define BITSET_SIZE(size) (((size) + BITSET_WORD_BITS - 1) / BITSET_WORD_BITS)

/**
 * Creates a bitset with the given number of bits.
 *
 * @internal
 * @param size the number of bits.
 * @return The initialized bitset with all bits set to 0.
 */
static inline bitset_t bitset_init(unsigned int size) {
  return (bitset_t){.bits = calloc(BITSET_SIZE(size), sizeof(uint64_t)), .size = size};
}

/**
 * Sets a specific bit of a bitset.
 *
 * @internal
 * @param bitset the bitset.
 * @param index  the index of the bit supposed to be set to 1.
 */
static inline void bitset_set(bitset_t* bitset, unsigned int index) {
  bitset->bits[index / BITSET_WORD_BITS] |= (UINT64_C(1) << (index & (BITSET_WORD_BITS - 1)));
}

/**
 * Retrieves a specific bit of a bitset.
 *
 * @internal
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
 * @internal
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
 * @internal
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

/**
 * Compute bloom filter size.
 *
 * @internal
 * @param n the desired size
 * @param false_positive_prob false positive probability
 * @return size of the bloom filter's bitset
 */
static inline unsigned int bf_get_needed_size(unsigned int n, double false_positive_prob) {
  return -floor((n * log(false_positive_prob)) / (log(2) * log(2)));
}

/**
 * Initialize bloom filter size with a fixed size and number of hash functions.
 *
 * @internal
 * @param size size of the bloom filter
 * @param hash_count number of hash functions
 * @return the bloom filter
 */
static inline bloomfilter_t bf_init_fixed(unsigned int size, unsigned int hash_count) {
  return (bloomfilter_t){.hash_count = hash_count, .bitset = bitset_init(size)};
}

/**
 * Initialize bloom filter from a desired size and a false positive probability.
 *
 * @internal
 * @param n desired size
 * @param false_positive_prob false positive probability
 * @return the bloom filter
 */
static inline bloomfilter_t bf_init(unsigned int n, double false_positive_prob) {
  const unsigned int bitset_size = bf_get_needed_size(n, false_positive_prob);

  return (bloomfilter_t){.hash_count = ceil((bitset_size / (double)n) * log(2)),
                         .bitset     = bitset_init(bitset_size)};
}

/**
 * Compute position on bloom filter for a given hash function
 *
 * @internal
 * @param hash_idx index of the hash function
 * @param input input data
 * @param input_len length of the input data
 * @param filter_size size of the bloom filter
 * @return position
 */
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
 * @internal
 * @param filter the bloom filter
 */
static inline void bf_reset(bloomfilter_t* filter) {
  memset(filter->bitset.bits, 0, BITSET_SIZE(filter->bitset.size) * sizeof(uint64_t));
}

/**
 * Clear and free up all memory of the bloom filter
 *
 * @internal
 * @param filter the bloom filter
 */
static inline void bf_clear(bloomfilter_t* filter) {
  if (filter) {
    bitset_clean(&filter->bitset);
  }
}

/**
 * Size of the serialized bloom filter
 *
 * @internal
 * @param filter filter to serialize
 * @return size (in bytes) if serialized
 */
static inline unsigned int bf_serialized_size(const bloomfilter_t* filter) {
  return 2 * sizeof(uint32_t) + BITSET_SIZE(filter->bitset.size) * sizeof(uint64_t);
}

/**
 * Write bloom filter to memory buffer.
 *
 * @internal
 * @param dst address of a pointer targeting the memory buffer; will be advanced by the number of
 * written bytes
 * @param filter the bloom filter to serialize
 */
static void bf_write(uint8_t** dst, const bloomfilter_t* filter) {
  write_u32(dst, filter->hash_count);
  write_u32(dst, filter->bitset.size);
  for (unsigned int i = 0; i < BITSET_SIZE(filter->bitset.size); ++i) {
    write_u64(dst, filter->bitset.bits[i]);
  }
}

/**
 * Read bloom filter from a memory buffer
 *
 * @internal
 * @param src address of a pointer targeting the memory buffer; will be advanced by tne number of
 * read bytes
 * @return the deserialized bloom filter
 */
static inline bloomfilter_t bf_read(const uint8_t** src) {
  const unsigned int hash_count  = read_u32(src);
  const unsigned int filter_size = read_u32(src);

  bloomfilter_t bloom_filter = bf_init_fixed(filter_size, hash_count);
  for (unsigned int i = 0; i < BITSET_SIZE(bloom_filter.bitset.size); ++i) {
    bloom_filter.bitset.bits[i] = read_u64(src);
  }
  return bloom_filter;
}

#endif
