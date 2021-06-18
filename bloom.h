#ifndef BLOOM_H
#define BLOOM_H

#include "include/types.h"

#include <stdbool.h>
#include <stdint.h>

struct bloom_filter {
  uint8_t* bitarray;
  unsigned int bitsize;
  unsigned int bytesize;
  unsigned int cells;
  unsigned int cellsize;
  unsigned int hashes;
};

/**
 * Computes the hash_idx-th hash function for the given input and maps it to the size of the Bloom
 * filter
 */
unsigned int bloom_get_position(unsigned int hash_idx, const void* input, unsigned int input_len,
                                unsigned int filter_size);

/**
 * Initializes a bloom filter with a bit array adn MurmurHash hash function.
 *
 * @param[in] cells         - the number of cells in the array of the bloom filter
 * @param[in] cellsize      - the number of bits per cell
 * @param[in] hashes        - the number of hash functions for the bloom filter
 *
 * @return a pointer to an initialized bloom filter.
 */
bloom_t bloom_init(unsigned int cells, unsigned int cellsize, unsigned int hashes);

/**
 * Adds the provided element to the bloom filter, and if the element already exists
 * it re-adds it.
 *
 * @param[in] bf            - the pointer to an initialized bloom filter
 * @param[in] item          - the item to be added to the bloom filter
 * @param[in] len           - the length of the item
 */
bool bloom_add(bloom_t bf, const void* item, unsigned int len);

/**
 * Checks if the provided element is in the bloom filter (can produce false positives).
 *
 * @param[in] bf            - the pointer to an initialized bloom filter
 * @param[in] item          - the item to be added to the bloom filter
 * @param[in] len           - the length of the item
 *
 * @return true if element is in the bloom filter, false otherwise.
 */
bool bloom_check(bloom_t bf, const void* item, unsigned int len);

/**
 * Removes the provided element from the bloom filter.
 *
 * @param[in] bf            - the pointer to an initialized bloom filter
 * @param[in] item          - the item to be added to the bloom filter
 * @param[in] len           - the length of the item
 *
 * @return true if no cell counter underflowed, false otherwise.
 */
bool bloom_remove(bloom_t bf, const void* item, unsigned int len);

/**
 * Resets the bit array of the provided bloom filter.
 *
 * @param[in] bf            - the pointer to an initialized bloom filter
 */
void bloom_reset(bloom_t bf);

/**
 * Serializes the given bloom filter.
 *
 * @param[in] dst            - buffer large enough to store serialized bloom filter
 * @param[in] bf             - the bloom filter that is serialized
 */
void bloom_serialize(uint8_t* dst, const bloom_t bf);

/**
 * Allocates memory and deserializes the given bloom filter.
 *
 * @param[in] serialized    - the serialized bloom filter
 *
 * @return a pointer to the deserialized bloom filter.
 */
bloom_t bloom_init_deserialize(const uint8_t* serialized);

/**
 * Returns the serialized size of the given bloom filter.
 *
 * @param[in] bf            - the pointer to an initialized bloom filter
 *
 * @return the serialized size of the bloom filter.
 */
unsigned bloom_get_size(bloom_t bf);

/**
 * Frees the given bloom filter.
 *
 * @param[in] bf            - the pointer to an initialized bloom filter
 */
void bloom_free(bloom_t bf);

#endif
