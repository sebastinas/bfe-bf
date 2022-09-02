#ifndef UTILS_H
#define UTILS_H

#include <endian.h>
#include <stdint.h>
#include <string.h>

#include <relic/relic.h>

#if !defined(RLC_TRY)
// error-handling macros have been renamed
#define RLC_TRY TRY
#define RLC_CATCH_ANY CATCH_ANY
#define RLC_FINALLY FINALLY
#endif

#include "FIPS202-opt64/KeccakHash.h"

#define G1_SIZE_COMPRESSED (1 + RLC_FP_BYTES)
#define G2_SIZE_COMPRESSED (1 + 2 * RLC_FP_BYTES)
#define GT_SIZE_COMPRESSED (8 * RLC_FP_BYTES)

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

/* helper functions for (de)serialization */

static inline void write_u8(uint8_t** dst, uint8_t v) {
  **dst = v;
  *dst += sizeof(v);
}

static inline uint8_t read_u8(const uint8_t** src) {
  uint8_t v = **src;
  *src += sizeof(v);
  return v;
}

static inline void write_u32(uint8_t** dst, uint32_t v) {
  v = htole32(v);
  memcpy(*dst, &v, sizeof(v));
  *dst += sizeof(v);
}

static inline uint32_t read_u32(const uint8_t** src) {
  uint32_t v;
  memcpy(&v, *src, sizeof(v));
  *src += sizeof(v);
  return le32toh(v);
}

static inline void write_u64(uint8_t** dst, uint64_t v) {
  v = htole64(v);
  memcpy(*dst, &v, sizeof(v));
  *dst += sizeof(v);
}

static inline uint64_t read_u64(const uint8_t** src) {
  uint64_t v;
  memcpy(&v, *src, sizeof(v));
  *src += sizeof(v);
  return le64toh(v);
}

static inline void write_bn(uint8_t** dst, const bn_t v) {
  bn_write_bin(*dst, RLC_BN_SIZE, v);
  *dst += RLC_BN_SIZE;
}

static inline void read_bn(bn_t v, const uint8_t** src) {
  bn_read_bin(v, *src, RLC_BN_SIZE);
  *src += RLC_BN_SIZE;
}

static inline void write_g1(uint8_t** dst, const g1_t v) {
  g1_write_bin(*dst, G1_SIZE_COMPRESSED, v, 1);
  *dst += G1_SIZE_COMPRESSED;
}

static inline void read_g1(g1_t v, const uint8_t** src) {
  g1_read_bin(v, *src, G1_SIZE_COMPRESSED);
  *src += G1_SIZE_COMPRESSED;
}

static inline void write_g2(uint8_t** dst, g2_t v) {
  g2_write_bin(*dst, G2_SIZE_COMPRESSED, v, 1);
  *dst += G2_SIZE_COMPRESSED;
}

static inline void read_g2(g2_t v, const uint8_t** src) {
  g2_read_bin(v, *src, G2_SIZE_COMPRESSED);
  *src += G2_SIZE_COMPRESSED;
}

static inline void write_gt(uint8_t** dst, gt_t v) {
  gt_write_bin(*dst, GT_SIZE_COMPRESSED, v, 1);
  *dst += GT_SIZE_COMPRESSED;
}

static inline void read_gt(gt_t v, const uint8_t** src) {
  gt_read_bin(v, *src, GT_SIZE_COMPRESSED);
  *src += GT_SIZE_COMPRESSED;
}

static inline void hash_update_g1(Keccak_HashInstance* ctx, const g1_t v) {
  uint8_t buffer[G1_SIZE_COMPRESSED];
  g1_write_bin(buffer, G1_SIZE_COMPRESSED, v, 1);
  Keccak_HashUpdate(ctx, buffer, G1_SIZE_COMPRESSED * 8);
}

static inline void hash_update_g2(Keccak_HashInstance* ctx, g2_t v) {
  uint8_t buffer[G2_SIZE_COMPRESSED];
  g2_write_bin(buffer, G2_SIZE_COMPRESSED, v, 1);
  Keccak_HashUpdate(ctx, buffer, G2_SIZE_COMPRESSED * 8);
}

static inline void hash_update_gt(Keccak_HashInstance* ctx, gt_t v) {
  uint8_t buffer[GT_SIZE_COMPRESSED];
  gt_write_bin(buffer, GT_SIZE_COMPRESSED, v, 1);
  Keccak_HashUpdate(ctx, buffer, GT_SIZE_COMPRESSED * 8);
}

#endif
