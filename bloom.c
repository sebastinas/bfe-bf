#include "bloom.h"

#include "FIPS202-opt64/KeccakHash.h"
#include "utils.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

typedef struct bloom_filter bloom_st;

bloom_t bloom_init(unsigned int cells, unsigned int cellsize, unsigned int hashes) {
  if (!cells || !hashes || !cellsize) {
    return NULL;
  }

  bloom_t bf = malloc(sizeof(bloom_st));
  if (bf == NULL) {
    return NULL;
  }

  bf->bitsize  = cells * cellsize;
  bf->bytesize = (bf->bitsize + 7) / 8;
  bf->cells    = cells;
  bf->cellsize = cellsize;
  bf->hashes   = hashes;
  bf->bitarray = calloc(1, sizeof(uint8_t) * bf->bytesize);
  if (bf->bitarray == NULL) {
    bloom_free(bf);
    return NULL;
  }

  return bf;
}

unsigned int bloom_get_position(unsigned int hash_idx, const void* input, unsigned int input_len,
                                unsigned int filter_size) {
  static const uint8_t domain[] = "BF_HASH";

  Keccak_HashInstance shake;
  Keccak_HashInitialize_SHAKE128(&shake);

  Keccak_HashUpdate(&shake, domain, sizeof(domain) * 8);
  uint32_t hash_idx_u32 = htole32(hash_idx);
  Keccak_HashUpdate(&shake, (const uint8_t*)&hash_idx_u32, sizeof(hash_idx_u32) * 8);
  Keccak_HashUpdate(&shake, input, input_len * 8);
  Keccak_HashFinal(&shake, NULL);

  uint64_t output = 0;
  Keccak_HashSqueeze(&shake, (uint8_t*)&output, sizeof(output) * 8);
  return le64toh(output) % filter_size;
}

bool bloom_add(bloom_t bf, const void* item, unsigned int len) {
  uint8_t* bitarray = bf->bitarray;
  unsigned int i, j;
  for (i = 0; i < bf->hashes; i++) {
    unsigned int hash = bloom_get_position(i, item, len, bf->cells);
    // Find the least significant bit.
    unsigned int lsb = hash * bf->cellsize;
    // Incrementing the counter by one is the same as starting from the least significant bit
    // flipping each bit until a bit is flipped from 0 to 1.
    for (j = 0; j < bf->cellsize; j++) {
      // Get the j-th bit of the cell.
      unsigned bit = bitarray[(lsb + j) / 8] & 1 << (lsb + j) % 8;
      // Flip the j-th bit.
      bitarray[(lsb + j) / 8] ^= 1 << (lsb + j) % 8;
      // If the j-th bit was 0 before being flipped, end the loop.
      if (bit) {
        // If we flipped each bit from 1 to 0 an overflow occurred.
        if (j == bf->cellsize - 1) {
          return false;
        }
      } else {
        break;
      }
    }
  }
  return true;
}

bool bloom_check(bloom_t bf, const void* item, unsigned int len) {
  uint8_t* bitarray = bf->bitarray;

  for (unsigned int i = 0; i < bf->hashes; i++) {
    unsigned int hash = bloom_get_position(i, item, len, bf->cells);
    unsigned int lsb  = hash * bf->cellsize;
    bool set          = false;
    // If each bit in the cell is 0, the item has not been added to the bloom filter.
    for (unsigned int j = 0; j < bf->cellsize; j++) {
      if (bitarray[(lsb + j) / 8] & 1 << (lsb + j) % 8) {
        set = true;
        break;
      }
    }
    if (!set) {
      return false;
    }
  }
  return true;
}

bool bloom_remove(bloom_t bf, const void* item, unsigned int len) {
  uint8_t* bitarray = bf->bitarray;
  unsigned int i, j;
  for (i = 0; i < bf->hashes; i++) {
    unsigned int hash = bloom_get_position(i, item, len, bf->cells);
    // Find the least significant bit.
    unsigned int lsb = hash * bf->cellsize;
    // Decrementing the counter by one is the same as starting from the least significant bit
    // flipping each bit until a bit is flipped from 1 to 0.
    for (j = 0; j < bf->cellsize; j++) {
      // Get the j-th bit.
      unsigned bit = bitarray[(lsb + j) / 8] & 1 << (lsb + j) % 8;
      // Flip the j-th bit.
      bitarray[(lsb + j) / 8] ^= 1 << (lsb + j) % 8;
      // If the j-th bit was 1 before being flipped, end the loop.
      if (bit) {
        break;
      } else {
        // If we flipped each bit from 0 to 1 an underflow occurred.
        if (j == bf->cellsize - 1) {
          return false;
        }
      }
    }
  }
  return true;
}

void bloom_reset(bloom_t bf) {
  memset(bf->bitarray, 0, sizeof(uint8_t) * bf->bytesize);
}

void bloom_serialize(uint8_t* dst, const bloom_t bf) {
  write_u32(&dst, bf->bitsize);
  write_u32(&dst, bf->cells);
  write_u32(&dst, bf->cellsize);
  write_u32(&dst, bf->hashes);
  memcpy(dst, bf->bitarray, sizeof(uint8_t) * bf->bytesize);
}

bloom_t bloom_init_deserialize(const uint8_t* serialized) {
  bloom_t bf = malloc(sizeof(bloom_st));
  if (!bf) {
    return NULL;
  }

  bf->bitsize  = read_u32(&serialized);
  bf->bytesize = (bf->bitsize + 7) / 8;
  bf->cells    = read_u32(&serialized);
  bf->cellsize = read_u32(&serialized);
  bf->hashes   = read_u32(&serialized);

  const unsigned bitarray_size = sizeof(uint8_t) * bf->bytesize;
  bf->bitarray                 = malloc(bitarray_size);
  if (bf->bitarray == NULL) {
    bloom_free(bf);
    return NULL;
  }
  memcpy(bf->bitarray, serialized, bitarray_size);

  return bf;
}

unsigned bloom_get_size(bloom_t bf) {
  const unsigned bitarray_size = sizeof(uint8_t) * bf->bytesize;
  return bitarray_size + (4 * sizeof(uint32_t));
}

void bloom_free(bloom_t bf) {
  if (bf) {
    free(bf->bitarray);
    bf->bitarray = NULL;
    bf->bitsize  = 0;
    bf->bytesize = 0;
    bf->cells    = 0;
    bf->cellsize = 0;
    bf->hashes   = 0;

    free(bf);
  }
}
