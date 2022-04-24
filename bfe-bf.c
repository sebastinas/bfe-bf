#include "include/bfe-bf.h"
#include "bloom.h"
#include "core.h"
#include "utils.h"

#include <config.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define EP_SIZE (1 + 2 * RLC_FP_BYTES)
#define EP2_SIZE (1 + 4 * RLC_FP_BYTES)
#define FP12_SIZE (12 * RLC_FP_BYTES)

static void bf_get_bit_positions(unsigned int* positions, const ep_t input, unsigned int hash_count,
                                 unsigned int filter_size) {
  const unsigned int buffer_size = ep_size_bin(input, 0);
  uint8_t buffer[EP_SIZE]        = {0};
  ep_write_bin(buffer, buffer_size, input, 0);

  for (unsigned int i = 0; i < hash_count; ++i) {
    positions[i] = bf_get_position(i, buffer, buffer_size, filter_size);
  }
}

/* Boneh-Franklin IBE implementation */

static int ibe_keygen(bn_t secret_key, bfe_bf_public_key_t* public_key) {
  int status = BFE_SUCCESS;

  TRY {
    zp_rand(secret_key);
    ep_mul_gen(public_key->public_key, secret_key);
  }
  CATCH_ANY {
    status = BFE_ERROR;
  }

  return status;
}

static int ibe_extract(ep2_t extracted_key, const bn_t secret_key, const uint8_t* id,
                       size_t id_size) {
  int status = BFE_SUCCESS;

  ep2_t qid;
  ep2_null(qid);
  TRY {
    ep2_new(qid);
    ep2_map(qid, id, id_size);
    ep2_mul(extracted_key, qid, secret_key);
  }
  CATCH_ANY {
    status = BFE_ERROR;
  }
  FINALLY {
    ep2_free(qid);
  }
  return status;
}

/* G(y) ^ K */
static void hash_and_xor(uint8_t* dst, size_t len, const uint8_t* input, fp12_t y) {
  static const uint8_t domain_G[] = "BFE_H_G";

  uint8_t buffer[FP12_SIZE] = {0};
  fp12_write_bin(buffer, FP12_SIZE, y, 0);

  Keccak_HashInstance shake;
  Keccak_HashInitialize_SHAKE256(&shake);
  Keccak_HashUpdate(&shake, domain_G, sizeof(domain_G) * 8);
  Keccak_HashUpdate(&shake, buffer, FP12_SIZE * 8);
  const uint64_t len_le = htole64(len);
  Keccak_HashUpdate(&shake, (const uint8_t*)&len_le, sizeof(len_le) * 8);
  Keccak_HashFinal(&shake, NULL);

  for (; len; len -= MIN(len, 64), dst += 64, input += 64) {
    uint8_t buf[64];
    const size_t l = MIN(len, 64);

    Keccak_HashSqueeze(&shake, buf, l * 8);
    /* make use of SIMD instructions */
#pragma omp simd
    for (size_t i = 0; i < l; ++i) {
      dst[i] = input[i] ^ buf[i];
    }
  }
}

/* R(K) */
static void hash_R(Keccak_HashInstance* ctx, const uint8_t* key, size_t key_size) {
  static const uint8_t domain_R[] = "BFE_H_R";

  Keccak_HashInitialize_SHAKE256(ctx);
  Keccak_HashUpdate(ctx, domain_R, sizeof(domain_R) * 8);
  Keccak_HashUpdate(ctx, key, key_size * 8);
  Keccak_HashFinal(ctx, NULL);
}

static int ibe_encrypt(uint8_t* dst, ep_t pkr, const uint8_t* id, size_t id_len,
                       const uint8_t* message, size_t message_len) {
  int status = BFE_SUCCESS;
  ep2_t qid;
  fp12_t t;

  ep2_null(qid);
  fp12_null(t);

  TRY {
    ep2_new(qid);
    fp12_new(t);

    /* G(i_j) */
    ep2_map(qid, id, id_len);
    /* e(pk^r, G(i_j)) */
    pp_map_k12(t, pkr, qid);

    hash_and_xor(dst, message_len, message, t);
  }
  CATCH_ANY {
    status = BFE_ERROR;
  }
  FINALLY {
    fp12_free(t);
    ep2_free(qid);
  };

  return status;
}

static int ibe_decrypt(uint8_t* message, ep_t g1r, const uint8_t* Kxored, size_t length,
                       ep2_t secret_key) {
  int status = BFE_SUCCESS;
  fp12_t t;
  fp12_null(t);

  TRY {
    fp12_new(t);
    pp_map_k12(t, g1r, secret_key);

    hash_and_xor(message, length, Kxored, t);
  }
  CATCH_ANY {
    status = BFE_ERROR;
  }
  FINALLY {
    fp12_free(t);
  };

  return status;
}

/* BFE implementation */

int bfe_bf_init_secret_key(bfe_bf_secret_key_t* secret_key) {
  memset(secret_key, 0, sizeof(bfe_bf_secret_key_t));
  return BFE_SUCCESS;
}

void bfe_bf_clear_secret_key(bfe_bf_secret_key_t* secret_key) {
  if (secret_key) {
    if (secret_key->secret_keys) {
      for (unsigned int i = 0; i < secret_key->secret_keys_len; ++i) {
        if (bitset_get(&secret_key->filter.bitset, i) == 0) {
          ep2_set_infty(secret_key->secret_keys[i]);
          ep2_free(secret_key->secret_keys[i]);
        }
      }
      free(secret_key->secret_keys);
      secret_key->secret_keys_len = 0;
      secret_key->secret_keys     = NULL;
    }
    bf_clear(&secret_key->filter);
  }
}

int bfe_bf_init_public_key(bfe_bf_public_key_t* public_key) {
  public_key->filter_hash_count = public_key->filter_size = public_key->key_size = 0;

  int status = BFE_SUCCESS;
  ep_null(public_key->public_key);
  TRY {
    ep_new(public_key->public_key);
  }
  CATCH_ANY {
    status = BFE_ERROR;
  }

  return status;
}

void bfe_bf_clear_public_key(bfe_bf_public_key_t* public_key) {
  if (public_key) {
    public_key->filter_hash_count = public_key->filter_size = public_key->key_size = 0;

    ep_free(public_key->public_key);
    ep_null(public_key->public_key);
  }
}

int bfe_bf_keygen(bfe_bf_public_key_t* public_key, bfe_bf_secret_key_t* secret_key,
                  unsigned int key_size, unsigned int filter_size, double false_positive_prob) {
  if (key_size > MAX_BFE_KEY_SIZE || order_size > MAX_ORDER_SIZE) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int status = BFE_SUCCESS;

  bloomfilter_t filter = bf_init(filter_size, false_positive_prob);
  if (filter.hash_count > MAX_BLOOMFILTER_HASH_COUNT) {
    bf_clear(&filter);
    return BFE_ERROR_INVALID_PARAM;
  }

  const unsigned int bf_size = filter.bitset.size;
  secret_key->secret_keys    = calloc(bf_size, sizeof(ep2_t));
  if (!secret_key->secret_keys) {
    bf_clear(&filter);
    return BFE_ERROR;
  }

  public_key->key_size          = key_size;
  public_key->filter_size       = bf_size;
  public_key->filter_hash_count = filter.hash_count;
  secret_key->secret_keys_len   = bf_size;
  secret_key->filter            = filter;

  bn_t sk;
  bn_null(sk);
  TRY {
    bn_new(sk);

    /* generate IBE key */
    status = ibe_keygen(sk, public_key);
    if (!status) {
      /* run key generation in parallel */
#pragma omp parallel for reduction(| : status)
      for (unsigned int i = 0; i < bf_size; ++i) {
        /* extract key for identity i */
        const uint64_t id = htole64(i);
        status |= ibe_extract(secret_key->secret_keys[i], sk, (const uint8_t*)&id, sizeof(id));
      }
    }
  }
  CATCH_ANY {
    status = BFE_ERROR;
  }
  FINALLY {
    bn_free(sk);
  }

  return status;
}

static int internal_encrypt(bfe_bf_ciphertext_t* ciphertext, const bfe_bf_public_key_t* public_key,
                            bn_t r, const uint8_t* K) {
  int status = BFE_SUCCESS;
  unsigned int bit_positions[MAX_BLOOMFILTER_HASH_COUNT];

  ep_t pkr;
  ep_null(pkr);

  TRY {
    ep_new(pkr);

    /* g_1^r */
    ep_mul_gen(ciphertext->u, r);
    /* pk^r */
    ep_mul(pkr, public_key->public_key, r);

    bf_get_bit_positions(bit_positions, ciphertext->u, public_key->filter_hash_count,
                         public_key->filter_size);

#pragma omp parallel for reduction(| : status)
    for (unsigned int i = 0; i < public_key->filter_hash_count; ++i) {
      const uint64_t id = htole64(bit_positions[i]);

      status |= ibe_encrypt(&ciphertext->v[i * public_key->key_size], pkr, (const uint8_t*)&id,
                            sizeof(id), K, public_key->key_size);
    }
  }
  CATCH_ANY {
    status = BFE_ERROR;
  }
  FINALLY {
    ep_free(pkr);
  }

  return status;
}

int bfe_bf_encaps(bfe_bf_ciphertext_t* ciphertext, uint8_t* Kout,
                  const bfe_bf_public_key_t* public_key) {
  uint8_t key_buffer[MAX_BFE_KEY_SIZE];
  rand_bytes(key_buffer, public_key->key_size);

  int status = BFE_SUCCESS;
  bn_t r;
  bn_null(r);

  TRY {
    bn_new(r);

    Keccak_HashInstance shake;
    hash_R(&shake, key_buffer, public_key->key_size);
    /* r of (r, K') = R(K) */
    hash_squeeze_zp(r, &shake);

    status = internal_encrypt(ciphertext, public_key, r, key_buffer);
    if (!status) {
      /* K' of (r, K') = R(K) */
      Keccak_HashSqueeze(&shake, Kout, public_key->key_size * 8);
    }
  }
  CATCH_ANY {
    status = BFE_ERROR;
  }
  FINALLY {
    bn_free(r);
  }
#if defined(HAVE_EXPLICIT_BZERO)
  explicit_bzero(key_buffer, sizeof(key_buffer));
#endif

  return status;
}

void bfe_bf_puncture(bfe_bf_secret_key_t* secret_key, bfe_bf_ciphertext_t* ciphertext) {
  unsigned int indices[MAX_BLOOMFILTER_HASH_COUNT];

  // bf_add(&secret_key->filter, ciphertext->u);
  bf_get_bit_positions(indices, ciphertext->u, secret_key->filter.hash_count,
                       secret_key->filter.bitset.size);
  for (unsigned int i = 0; i < secret_key->filter.hash_count; ++i) {
    bitset_set(&secret_key->filter.bitset, indices[i]);
    ep2_set_infty(secret_key->secret_keys[indices[i]]);
    ep2_free(secret_key->secret_keys[indices[i]]);
  }
}

static int bfe_bf_ciphertext_cmp(const bfe_bf_ciphertext_t* ciphertext1,
                                 const bfe_bf_ciphertext_t* ciphertext2) {
  if (ep_cmp(ciphertext1->u, ciphertext2->u) != RLC_EQ ||
      ciphertext1->v_size != ciphertext2->v_size) {
    return 1;
  }

  return memcmp(ciphertext1->v, ciphertext2->v, ciphertext1->v_size);
}

int bfe_bf_decaps(uint8_t* key, const bfe_bf_public_key_t* public_key,
                  const bfe_bf_secret_key_t* secret_key, bfe_bf_ciphertext_t* ciphertext) {
  int status = BFE_SUCCESS;

  uint8_t key_buffer[MAX_BFE_KEY_SIZE];
  unsigned int indices[MAX_BLOOMFILTER_HASH_COUNT];

  bf_get_bit_positions(indices, ciphertext->u, secret_key->filter.hash_count,
                       secret_key->filter.bitset.size);

  status = BFE_ERROR;
  for (unsigned int i = 0; i < secret_key->filter.hash_count; ++i) {
    if (bitset_get(&secret_key->filter.bitset, indices[i]) == 0) {
      status = ibe_decrypt(key_buffer, ciphertext->u, &ciphertext->v[i * public_key->key_size],
                           public_key->key_size, secret_key->secret_keys[indices[i]]);
      if (status == BFE_SUCCESS) {
        break;
      }
    }
  }

  if (status != BFE_SUCCESS) {
    return BFE_ERROR_KEY_PUNCTURED;
  }

  bfe_bf_ciphertext_t check_ciphertext;
  bfe_bf_init_ciphertext(&check_ciphertext, public_key);

  bn_t r;
  bn_null(r);

  TRY {
    bn_new(r);

    Keccak_HashInstance shake;
    hash_R(&shake, key_buffer, public_key->key_size);
    /* r of (r, K') = R(K) */
    hash_squeeze_zp(r, &shake);

    status = internal_encrypt(&check_ciphertext, public_key, r, key_buffer);

    if (!status && !bfe_bf_ciphertext_cmp(&check_ciphertext, ciphertext)) {
      /* K' of (r, K') = R(K) */
      Keccak_HashSqueeze(&shake, key, public_key->key_size * 8);
    } else {
      status = BFE_ERROR;
    }
  }
  CATCH_ANY {
    status = BFE_ERROR;
  }
  FINALLY {
    bn_free(r);
    bfe_bf_clear_ciphertext(&check_ciphertext);
  }
#if defined(HAVE_EXPLICIT_BZERO)
  explicit_bzero(key_buffer, sizeof(key_buffer));
#endif

  return status;
}

static int init_ciphertext(bfe_bf_ciphertext_t* ciphertext, unsigned int hash_count,
                           unsigned int key_length) {
  int status = BFE_SUCCESS;

  ep_null(ciphertext->u);
  TRY {
    ep_new(ciphertext->u);
  }
  CATCH_ANY {
    status = BFE_ERROR;
  }

  if (!status) {
    ciphertext->v_size = hash_count * key_length;
    ciphertext->v      = calloc(hash_count, key_length);
    if (!ciphertext->v) {
      status = BFE_ERROR;
    }
  }

  return status;
}

int bfe_bf_init_ciphertext(bfe_bf_ciphertext_t* ciphertext, const bfe_bf_public_key_t* public_key) {
  return init_ciphertext(ciphertext, public_key->filter_hash_count, public_key->key_size);
}

void bfe_bf_clear_ciphertext(bfe_bf_ciphertext_t* ciphertext) {
  if (ciphertext) {
    free(ciphertext->v);
    ep_free(ciphertext->u);
    ciphertext->v_size = 0;
    ciphertext->v      = NULL;
  }
}

unsigned int bfe_bf_ciphertext_size(const bfe_bf_ciphertext_t* ciphertext) {
  return 1 * sizeof(uint32_t) + EP_SIZE + ciphertext->v_size;
}

void bfe_bf_ciphertext_serialize(uint8_t* dst, const bfe_bf_ciphertext_t* ciphertext) {
  const uint32_t u_size     = EP_SIZE;
  const uint32_t total_size = bfe_bf_ciphertext_size(ciphertext);

  write_u32(&dst, total_size);

  ep_write_bin(dst, EP_SIZE, ciphertext->u, 0);
  memcpy(&dst[u_size], ciphertext->v, ciphertext->v_size);
}

int bfe_bf_ciphertext_deserialize(bfe_bf_ciphertext_t* ciphertext, const uint8_t* src) {
  const uint32_t total_size = read_u32(&src);
  const unsigned int v_size = total_size - EP_SIZE - 1 * sizeof(uint32_t);

  if (init_ciphertext(ciphertext, 1, v_size)) {
    return BFE_ERROR;
  }

  int status = BFE_SUCCESS;
  TRY {
    ep_read_bin(ciphertext->u, src, EP_SIZE);
    ciphertext->v_size = v_size;
    memcpy(ciphertext->v, &src[EP_SIZE], v_size);
  }
  CATCH_ANY {
    status = BFE_ERROR;
  }

  return status;
}

unsigned int bfe_bf_public_key_size(void) {
  return 3 * sizeof(uint32_t) + EP_SIZE;
}

void bfe_bf_public_key_serialize(uint8_t* dst, const bfe_bf_public_key_t* public_key) {
  write_u32(&dst, public_key->filter_hash_count);
  write_u32(&dst, public_key->filter_size);
  write_u32(&dst, public_key->key_size);
  ep_write_bin(dst, EP_SIZE, public_key->public_key, 0);
}

int bfe_bf_public_key_deserialize(bfe_bf_public_key_t* public_key, const uint8_t* src) {
  public_key->filter_hash_count = read_u32(&src);
  public_key->filter_size       = read_u32(&src);
  public_key->key_size          = read_u32(&src);

  int status = BFE_SUCCESS;
  TRY {
    ep_read_bin(public_key->public_key, src, EP_SIZE);
  }
  CATCH_ANY {
    status = BFE_ERROR;
  }

  return status;
}

unsigned int bfe_bf_secret_key_size(const bfe_bf_secret_key_t* secret_key) {
  unsigned int num_keys =
      secret_key->filter.bitset.size - bitset_popcount(&secret_key->filter.bitset);

  return bf_serialized_size(&secret_key->filter) + num_keys * EP2_SIZE;
}

void bfe_bf_secret_key_serialize(uint8_t* dst, const bfe_bf_secret_key_t* secret_key) {
  bf_write(&dst, &secret_key->filter);
  for (unsigned int i = 0; i < secret_key->filter.bitset.size; ++i) {
    if (bitset_get(&secret_key->filter.bitset, i) == 0) {
      ep2_write_bin(dst, EP2_SIZE, secret_key->secret_keys[i], 0);
      dst += EP2_SIZE;
    }
  }
}

int bfe_bf_secret_key_deserialize(bfe_bf_secret_key_t* secret_key, const uint8_t* src) {
  secret_key->filter          = bf_read(&src);
  secret_key->secret_keys_len = secret_key->filter.bitset.size;
  secret_key->secret_keys     = calloc(secret_key->filter.bitset.size, sizeof(ep2_t));

  int status = BFE_SUCCESS;
  TRY {
    for (unsigned int i = 0; i < secret_key->filter.bitset.size; ++i) {
      if (bitset_get(&secret_key->filter.bitset, i) == 0) {
        ep2_new(secret_key->secret_keys[i]);
        ep2_read_bin(secret_key->secret_keys[i], src, EP2_SIZE);
        src += EP2_SIZE;
      }
    }
  }
  CATCH_ANY {
    status = BFE_ERROR;
  }

  return status;
}
