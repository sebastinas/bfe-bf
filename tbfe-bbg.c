#include "include/tbfe-bbg.h"

#include "bloom.h"
#include "core.h"
#include "utils.h"
#include "vector.h"

#include <assert.h>
#include <math.h>
#include <omp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define BBG_CIPHERTEXT_SIZE (G1_SIZE_COMPRESSED + G2_SIZE_COMPRESSED + GT_SIZE_COMPRESSED)
#define BBG_PUBLIC_KEY_SIZE GT_SIZE_COMPRESSED

#define OTS_SIZE (2 * RLC_BN_SIZE)
#define OTS_PUBLIC_KEY_SIZE (3 * G1_SIZE_COMPRESSED)

typedef struct {
  unsigned depth;
  unsigned* id;
} bbg_identity_t;

typedef struct {
  gt_t k;
} bbg_key_t;

typedef struct {
  g1_t mk;
} bbg_master_key_t;

typedef struct {
  unsigned num_delegatable_levels;
  bbg_identity_t identity;
  g1_t a0;
  g2_t a1;
  g1_t associated_id;
  g1_t* b;
} bbg_secret_key_t;

typedef struct {
  gt_t a;
  g2_t b;
  g1_t c;
} bbg_ciphertext_t;

typedef struct {
  bn_t xs;
  bn_t ys;
  bn_t rs;
  bn_t ss;
} bbg_ots_sk_t;

static const uint8_t IDENTITY_PREFIX     = 2;
static const uint8_t SIGNATURE_PREFIX    = 3;
static const uint8_t VERIFICATION_PREFIX = 4;

static void bbg_deserialize_identity(bbg_identity_t* identity, const uint8_t* src);

static void bbg_serialize_ciphertext(uint8_t* serialized, bbg_ciphertext_t* ciphertext) {
  write_gt(&serialized, ciphertext->a);
  write_g2(&serialized, ciphertext->b);
  write_g1(&serialized, ciphertext->c);
}

static void bbg_deserialize_ciphertext(bbg_ciphertext_t* ciphertext, const uint8_t* serialized) {
  read_gt(ciphertext->a, &serialized);
  read_g2(ciphertext->b, &serialized);
  read_g1(ciphertext->c, &serialized);
}

static void hash_update_bbg_ciphertext(Keccak_HashInstance* ctx, bbg_ciphertext_t* ciphertext) {
  hash_update_gt(ctx, ciphertext->a);
  hash_update_g2(ctx, ciphertext->b);
  hash_update_g1(ctx, ciphertext->c);
}

static void hash_update_bbg_ciphertexts(Keccak_HashInstance* ctx, vector_t* ciphertexts) {
  const unsigned int count = vector_size(ciphertexts);
  for (size_t i = 0; i < count; ++i) {
    hash_update_bbg_ciphertext(ctx, vector_get(ciphertexts, i));
  }
}

static void hash_update_ots_pk(Keccak_HashInstance* ctx, bbg_ots_pk_t* ots_pk) {
  hash_update_g1(ctx, ots_pk->fs);
  hash_update_g1(ctx, ots_pk->hs);
  hash_update_g1(ctx, ots_pk->cs);
}

static int bbg_init_identity(bbg_identity_t* identity, unsigned int id_depth) {
  if (!identity) {
    return BFE_ERROR_INVALID_PARAM;
  }

  identity->id = calloc(id_depth, sizeof(*identity->id));
  if (!identity->id) {
    return BFE_ERROR;
  }
  identity->depth = id_depth;
  return BFE_SUCCESS;
}

static void bbg_clear_identity(bbg_identity_t* identity) {
  if (identity) {
    free(identity->id);
    identity->id    = NULL;
    identity->depth = 0;
  }
}

static int bbg_copy_identity(bbg_identity_t* dest, const bbg_identity_t* src) {
  if (!dest || !src || dest->depth != src->depth) {
    return BFE_ERROR_INVALID_PARAM;
  }

  memcpy(dest->id, src->id, sizeof(src->id[0]) * src->depth);
  return BFE_SUCCESS;
}

static bool bbg_identities_are_equal(const bbg_identity_t* l, const bbg_identity_t* r) {
  return l->depth == r->depth && memcmp(l->id, r->id, sizeof(l->id[0]) * l->depth) == 0;
}

static unsigned int bbg_get_identity_size(const bbg_identity_t* identity) {
  return (identity->depth + 1) * sizeof(uint32_t);
}

static int bbg_init_master_key(bbg_master_key_t* mk) {
  if (!mk) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int ret = BFE_SUCCESS;

  g1_null(mk->mk);
  TRY {
    g1_new(mk->mk);
  }
  CATCH_ANY {
    ret = BFE_ERROR;
  }
  return ret;
}

static void bbg_clear_master_key(bbg_master_key_t* mk) {
  if (mk) {
    g1_set_infty(mk->mk);
    g1_free(mk->mk);
  }
}

static int bbg_init_public_key(bbg_public_key_t* pk) {
  if (!pk) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int ret = BFE_SUCCESS;

  gt_null(pk->pk);
  TRY {
    gt_new(pk->pk);
  }
  CATCH_ANY {
    ret = BFE_ERROR;
  }
  return ret;
}

static void bbg_clear_public_key(bbg_public_key_t* pk) {
  if (pk) {
    gt_free(pk->pk);
  }
}

static int bbg_init_public_params(bbg_public_params_t* params, unsigned int depth) {
  if (!params || depth < 3) {
    return BFE_ERROR_INVALID_PARAM;
  }

  params->max_delegatable_depth = depth - 1;
  params->h                     = calloc(depth, sizeof(*params->h));
  params->h_precomputation_tables =
      calloc(depth * RLC_EP_TABLE, sizeof(*params->h_precomputation_tables));
  if (!params->h || !params->h_precomputation_tables) {
    free(params->h);
    return BFE_ERROR;
  }

  g1_null(params->g);
  g2_null(params->g_hat);
  g1_null(params->g2);
  g1_null(params->g3);
  for (size_t i = 0; i < depth; ++i) {
    g1_null(params->h[i]);
  }
  for (size_t i = 0; i < depth * RLC_EP_TABLE; ++i) {
    g1_null(params->h_precomputation_tables[i]);
  }

  int ret = BFE_SUCCESS;
  TRY {
    g1_new(params->g);
    g2_new(params->g_hat);
    g1_new(params->g2);
    g1_new(params->g3);
    for (size_t i = 0; i < depth; ++i) {
      g1_new(params->h[i]);
    }
    for (size_t i = 0; i < depth * RLC_EP_TABLE; ++i) {
      g1_new(params->h_precomputation_tables[i]);
    }
  }
  CATCH_ANY {
    ret = BFE_ERROR;
  }

  return ret;
}

static int bbg_init_public_params_from_serialized(bbg_public_params_t* params,
                                                  const uint8_t* serialized) {
  if (!params || !serialized) {
    return BFE_ERROR_INVALID_PARAM;
  }

  const unsigned int depth = read_u32(&serialized) + 1;
  if (bbg_init_public_params(params, depth) != BFE_SUCCESS) {
    return BFE_ERROR;
  }

  int ret = BFE_SUCCESS;
  TRY {
    read_g1(params->g, &serialized);
    read_g2(params->g_hat, &serialized);
    read_g1(params->g2, &serialized);
    read_g1(params->g3, &serialized);

    for (size_t i = 0; i < params->max_delegatable_depth + 1; ++i) {
      read_g1(params->h[i], &serialized);
      g1_mul_pre(params->h_precomputation_tables + i * RLC_EP_TABLE, params->h[i]);
    }
  }
  CATCH_ANY {
    ret = BFE_ERROR;
  }

  return ret;
}

static void bbg_clear_public_params(bbg_public_params_t* params) {
  if (params) {
    g1_free(params->g);
    g2_free(params->g_hat);
    g1_free(params->g2);
    g1_free(params->g3);
    if (params->h_precomputation_tables) {
      for (size_t i = 0; i < (params->max_delegatable_depth + 1) * RLC_EP_TABLE; ++i) {
        g1_free(params->h_precomputation_tables[i]);
      }
      free(params->h_precomputation_tables);
      params->h_precomputation_tables = NULL;
    }
    if (params->h) {
      for (size_t i = 0; i < params->max_delegatable_depth + 1; ++i) {
        g1_free(params->h[i]);
      }
      free(params->h);
      params->h = NULL;
    }
    params->max_delegatable_depth = 0;
  }
}

static int bbg_init_secret_key(bbg_secret_key_t* sk, unsigned int delegetable_levels,
                               unsigned int id_depth) {
  if (!sk) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int ret = bbg_init_identity(&sk->identity, id_depth);
  if (ret != BFE_SUCCESS) {
    return ret;
  }

  g1_null(sk->a0);
  g2_null(sk->a1);
  g1_null(sk->associated_id);

  sk->b = calloc(delegetable_levels, sizeof(*sk->b));
  if (!sk->b) {
    return ret;
  }
  sk->num_delegatable_levels = delegetable_levels;

  for (size_t idx = 0; idx < delegetable_levels; ++idx) {
    g1_null(sk->b[idx]);
  }

  TRY {
    g1_new(sk->a0);
    g2_new(sk->a1);
    g1_new(sk->associated_id);

    for (size_t idx = 0; idx < delegetable_levels; ++idx) {
      g1_new(sk->b[idx]);
    }
  }
  CATCH_ANY {
    ret = BFE_ERROR;
  }

  return ret;
}

static void bbg_clear_secret_key(bbg_secret_key_t* sk) {
  if (sk) {
    for (size_t idx = sk->num_delegatable_levels; idx; --idx) {
      g1_set_infty(sk->b[idx - 1]);
      g1_free(sk->b[idx - 1]);
    }
    free(sk->b);
    sk->b = NULL;

    g1_set_infty(sk->associated_id);
    g1_free(sk->associated_id);
    g2_set_infty(sk->a1);
    g2_free(sk->a1);
    g1_set_infty(sk->a0);
    g1_free(sk->a0);

    bbg_clear_identity(&sk->identity);
  }
}

static int ots_init_sk(bbg_ots_sk_t* ots_sk) {
  if (!ots_sk) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int ret = BFE_SUCCESS;

  bn_null(ots_sk->xs);
  bn_null(ots_sk->ys);
  bn_null(ots_sk->rs);
  bn_null(ots_sk->ss);

  TRY {
    bn_new(ots_sk->xs);
    bn_new(ots_sk->ys);
    bn_new(ots_sk->rs);
    bn_new(ots_sk->ss);
  }
  CATCH_ANY {
    ret = BFE_ERROR;
  }

  return ret;
}

static void ots_clear_sk(bbg_ots_sk_t* ots_sk) {
  if (ots_sk) {
    bn_set_dig(ots_sk->xs, 0);
    bn_set_dig(ots_sk->ys, 0);
    bn_set_dig(ots_sk->rs, 0);
    bn_set_dig(ots_sk->ss, 0);

    bn_free(ots_sk->ss);
    bn_free(ots_sk->rs);
    bn_free(ots_sk->ys);
    bn_free(ots_sk->xs);
  }
}

static int bbg_init_ots_public_key(bbg_ots_pk_t* ots_pk) {
  if (!ots_pk) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int ret = BFE_SUCCESS;

  g1_null(ots_pk->fs);
  g1_null(ots_pk->hs);
  g1_null(ots_pk->cs);

  TRY {
    g1_new(ots_pk->fs);
    g1_new(ots_pk->hs);
    g1_new(ots_pk->cs);
  }
  CATCH_ANY {
    ret = BFE_ERROR;
  }

  return ret;
}

static void bbg_clear_ots_public_key(bbg_ots_pk_t* ots_pk) {
  if (ots_pk) {
    g1_free(ots_pk->fs);
    g1_free(ots_pk->hs);
    g1_free(ots_pk->cs);
  }
}

static int bbg_init_ots(bbg_ots_t* ots) {
  if (!ots) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int ret = BFE_SUCCESS;

  bn_null(ots->r);
  bn_null(ots->s);
  TRY {
    bn_new(ots->r);
    bn_new(ots->s);
  }
  CATCH_ANY {
    ret = BFE_ERROR;
  }

  return ret;
}

static void bbg_clear_ots(bbg_ots_t* ots) {
  if (ots) {
    bn_free(ots->s);
    bn_free(ots->r);
  }
}

static int bbg_init_ciphertext(bbg_ciphertext_t* ciphertext) {
  if (!ciphertext) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int ret = BFE_SUCCESS;

  gt_null(ciphertext->a);
  g2_null(ciphertext->b);
  g1_null(ciphertext->c);

  TRY {
    gt_new(ciphertext->a);
    g2_new(ciphertext->b);
    g1_new(ciphertext->c);
  }
  CATCH_ANY {
    ret = BFE_ERROR;
  }

  return ret;
}

static void bbg_clear_ciphertext(bbg_ciphertext_t* ciphertext) {
  if (ciphertext) {
    g1_free(ciphertext->c);
    g2_free(ciphertext->b);
    gt_free(ciphertext->a);
  }
}

static int bbg_init_key(bbg_key_t* key) {
  if (!key) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int ret = BFE_SUCCESS;

  gt_null(key->k);
  TRY {
    gt_new(key->k);
  }
  CATCH_ANY {
    ret = BFE_ERROR;
  }

  return ret;
}

static int bbg_sample_key(bbg_key_t* key) {
  if (!key) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int ret = BFE_SUCCESS;
  TRY {
    gt_rand(key->k);
  }
  CATCH_ANY {
    ret = BFE_ERROR;
  }
  return ret;
}

static void bbg_clear_key(bbg_key_t* key) {
  if (key) {
    gt_zero(key->k);
    gt_free(key->k);
  }
}

static int bbg_setup(bbg_master_key_t* master_key, bbg_public_key_t* public_key,
                     bbg_public_params_t* public_params, const unsigned total_depth) {
  int result_status = BFE_SUCCESS;

  g2_t original_public_key_pk;
  g2_null(original_public_key_pk);

  bn_t alpha;
  bn_null(alpha);

  TRY {
    g2_new(original_public_key_pk);
    bn_new(alpha);

    g1_rand(public_params->g);
    g2_rand(public_params->g_hat);
    g1_rand(public_params->g2);
    g1_rand(public_params->g3);

    for (size_t i = 0; i < total_depth; ++i) {
      g1_rand(public_params->h[i]);
      g1_mul_pre(public_params->h_precomputation_tables + i * RLC_EP_TABLE, public_params->h[i]);
    }

    // Choose a random alpha from Z_p^*.
    zp_rand(alpha);

    // We precompute e(g_2, \pk), and save it as our actual public key.
    g2_mul(original_public_key_pk, public_params->g_hat, alpha);
    pc_map(public_key->pk, public_params->g2, original_public_key_pk);

    g1_mul(master_key->mk, public_params->g2, alpha);

    public_params->max_delegatable_depth = total_depth - 1;
  }
  CATCH_ANY {
    result_status = BFE_ERROR;
  }
  FINALLY {
    bn_free(alpha);
    g2_free(original_public_key_pk);
  }

  return result_status;
}

static void bbg_hash_id(bn_t hashed_id, const unsigned id, const unsigned prefix) {
  const uint32_t prefix_u32 = htole32(prefix);
  const uint32_t id_u32     = htole32(id);

  Keccak_HashInstance ctx;
  Keccak_HashInitialize_SHAKE128(&ctx);
  Keccak_HashUpdate(&ctx, (const uint8_t*)&prefix_u32, sizeof(prefix_u32) * 8);
  Keccak_HashUpdate(&ctx, (const uint8_t*)&id_u32, sizeof(id_u32) * 8);
  Keccak_HashFinal(&ctx, NULL);
  hash_squeeze_zp(hashed_id, &ctx);
}

static int bbg_convert_identity_to_zp_vector(bn_t* identity_zp_vector,
                                             const bbg_identity_t* identity) {
  int result_status = BFE_SUCCESS;

  for (size_t i = 0; i < identity->depth; ++i) {
    bn_null(identity_zp_vector[i]);
  }

  TRY {
    for (size_t i = 0; i < identity->depth; ++i) {
      bn_new(identity_zp_vector[i]);
      bbg_hash_id(identity_zp_vector[i], identity->id[i], IDENTITY_PREFIX);
    }
  }
  CATCH_ANY {
    result_status = BFE_ERROR;
  }

  return result_status;
}

static int bbg_key_generation_from_master_key(bbg_secret_key_t* secret_key,
                                              bbg_master_key_t* master_key,
                                              const bbg_identity_t* identity,
                                              bbg_public_params_t* public_params) {
  const unsigned total_depth            = public_params->max_delegatable_depth + 1;
  const unsigned num_total_levels       = total_depth - identity->depth;
  const unsigned num_delegatable_levels = num_total_levels - 1;

  int result_status = BFE_SUCCESS;

  g1_t h_i_to_the_identity_i;
  bn_t* identity_zp_vector = calloc(sizeof(*identity_zp_vector), identity->depth);
  bn_t v;

  g1_null(h_i_to_the_identity_i);
  bn_null(v);

  TRY {
    g1_new(secret_key_associated_id);

    g1_new(h_i_to_the_identity_i);
    bn_new(v);

    bbg_convert_identity_to_zp_vector(identity_zp_vector, identity);

    // Choose a random v from Z_p^*.
    zp_rand(v);

    // Computation of a_0 = mk * (prod_{i=1 to k} h_i^{H(0||I_i)} * g3)^v.
    g1_copy(secret_key->associated_id, public_params->g3);

    for (size_t i = 0; i < identity->depth; ++i) {
      g1_mul_fix(h_i_to_the_identity_i, &public_params->h_precomputation_tables[i * RLC_EP_TABLE],
                 identity_zp_vector[i]);
      g1_add(secret_key->associated_id, secret_key->associated_id, h_i_to_the_identity_i);
    }

    g1_mul(secret_key->a0, secret_key->associated_id, v);
    g1_add(secret_key->a0, master_key->mk, secret_key->a0);
    g2_mul(secret_key->a1, public_params->g_hat, v);

    for (size_t i = 0; i < num_total_levels; ++i) {
      g1_mul_fix(secret_key->b[i],
                 &public_params->h_precomputation_tables[(identity->depth + i) * RLC_EP_TABLE], v);
    }

    result_status                      = bbg_copy_identity(&secret_key->identity, identity);
    secret_key->num_delegatable_levels = num_delegatable_levels;
  }
  CATCH_ANY {
    result_status = BFE_ERROR;
  }
  FINALLY {
    g1_free(h_i_to_the_identity_i);

    for (size_t i = 0; i < identity->depth; ++i) {
      bn_free(identity_zp_vector[i]);
    }
    free(identity_zp_vector);

    bn_free(v);
  }

  return result_status;
}

static int bbg_key_generation_from_parent(bbg_secret_key_t* secret_key,
                                          bbg_secret_key_t* parent_secret_key,
                                          const bbg_identity_t* identity,
                                          bbg_public_params_t* public_params) {

  const unsigned total_depth = public_params->max_delegatable_depth + 1;
  const unsigned parent_depth =
      public_params->max_delegatable_depth - parent_secret_key->num_delegatable_levels;
  if (parent_depth != (identity->depth - 1)) {
    return BFE_ERROR_INVALID_PARAM;
  }

  const unsigned num_total_levels       = total_depth - identity->depth;
  const unsigned num_delegatable_levels = num_total_levels - 1;

  int result_status = BFE_SUCCESS;

  bn_t w;
  bn_t u;

  bn_null(w);
  bn_null(u);

  TRY {
    bn_new(w);
    bn_new(u);

    bbg_hash_id(w, identity->id[identity->depth - 1], IDENTITY_PREFIX);

    g1_mul_fix(secret_key->associated_id,
               &public_params->h_precomputation_tables[(identity->depth - 1) * RLC_EP_TABLE], w);
    g1_add(secret_key->associated_id, parent_secret_key->associated_id, secret_key->associated_id);

    // Choose a random w from Z_p^*.
    zp_rand(u);
    g1_mul_sim(secret_key->a0, parent_secret_key->b[0], w, secret_key->associated_id, u);
    g1_add(secret_key->a0, secret_key->a0, parent_secret_key->a0);

    g2_mul(secret_key->a1, public_params->g_hat, u);
    g2_add(secret_key->a1, parent_secret_key->a1, secret_key->a1);

    for (size_t i = 0; i < num_total_levels; ++i) {
      g1_mul_fix(secret_key->b[i],
                 &public_params->h_precomputation_tables[(identity->depth + i) * RLC_EP_TABLE], u);
      g1_add(secret_key->b[i], secret_key->b[i], parent_secret_key->b[i + 1]);
    }

    result_status                      = bbg_copy_identity(&secret_key->identity, identity);
    secret_key->num_delegatable_levels = num_delegatable_levels;
  }
  CATCH_ANY {
    result_status = BFE_ERROR;
  }
  FINALLY {
    bn_free(u);
    bn_free(w);
  }

  return result_status;
}

static int bbg_encapsulate(bbg_ciphertext_t* ciphertext, gt_t message, bbg_public_key_t* public_key,
                           bbg_ots_pk_t* ots_public_key, bbg_public_params_t* public_params,
                           const bbg_identity_t* identity) {
  bn_t* identity_zp_vector = calloc(sizeof(*identity_zp_vector), identity->depth);
  if (!identity_zp_vector) {
    return BFE_ERROR;
  }
  int result_status = bbg_convert_identity_to_zp_vector(identity_zp_vector, identity);
  if (result_status) {
    goto clean;
  }

  bn_t u;
  bn_null(u);
  g1_t tmp;
  g1_null(tmp);
  TRY {
    bn_new(u);
    g1_new(tmp);

    {
      Keccak_HashInstance ctx;
      Keccak_HashInitialize_SHAKE256(&ctx);
      Keccak_HashUpdate(&ctx, &VERIFICATION_PREFIX, sizeof(VERIFICATION_PREFIX) * 8);
      hash_update_ots_pk(&ctx, ots_public_key);
      Keccak_HashFinal(&ctx, NULL);
      hash_squeeze_zp(u, &ctx);
    }

    // Compute the encryption.
    g1_copy(ciphertext->c, public_params->g3);
    for (size_t i = 0; i < identity->depth; ++i) {
      g1_mul_fix(tmp, &public_params->h_precomputation_tables[i * RLC_EP_TABLE],
                 identity_zp_vector[i]);
      g1_add(ciphertext->c, ciphertext->c, tmp);
    }

    g1_mul_fix(tmp, &public_params->h_precomputation_tables[identity->depth * RLC_EP_TABLE], u);
    g1_add(ciphertext->c, ciphertext->c, tmp);

    // Choose a random s from Z_p^*.
    zp_rand(u);
    gt_exp(ciphertext->a, public_key->pk, u);
    gt_mul(ciphertext->a, ciphertext->a, message);
    g2_mul(ciphertext->b, public_params->g_hat, u);
    g1_mul(ciphertext->c, ciphertext->c, u);
  }
  CATCH_ANY {
    result_status = BFE_ERROR;
  }
  FINALLY {
    g1_free(tmp);
    bn_free(u);
  }

clean:
  for (size_t i = 0; i < identity->depth; ++i) {
    bn_free(identity_zp_vector[i]);
  }
  free(identity_zp_vector);
  return result_status;
}

static int bbg_decapsulate(bbg_key_t* key, bbg_ciphertext_t* ciphertext,
                           bbg_secret_key_t* secret_key, bbg_ots_pk_t* ots_public_key,
                           bbg_public_params_t* public_params, const bbg_identity_t* identity) {
  bn_t* identity_zp_vector = calloc(sizeof(*identity_zp_vector), identity->depth);
  if (!identity_zp_vector) {
    return BFE_ERROR;
  }
  int result_status = bbg_convert_identity_to_zp_vector(identity_zp_vector, identity);
  if (result_status) {
    goto clear;
  }

  bn_t u;
  bn_t w;
  bn_null(u);
  bn_null(w);

  g1_t g1s[2];
  g2_t g2s[2];
  g1_null(g1s[0]);
  g1_null(g1s[1]);
  g2_null(g2s[0]);
  g2_null(g2s[1]);

  TRY {
    bn_new(u);
    bn_new(w);
    g1_new(g1s[0]);
    g1_new(g1s[1]);
    g2_new(g2s[0]);
    g2_new(g2s[1]);

    {
      Keccak_HashInstance ctx;
      Keccak_HashInitialize_SHAKE256(&ctx);
      Keccak_HashUpdate(&ctx, &VERIFICATION_PREFIX, sizeof(VERIFICATION_PREFIX) * 8);
      hash_update_ots_pk(&ctx, ots_public_key);
      Keccak_HashFinal(&ctx, NULL);
      hash_squeeze_zp(u, &ctx);
    }

    // Choose a random w from Z_p^*.
    zp_rand(w);

    g1_copy(g1s[0], public_params->g3);
    for (size_t i = 0; i < identity->depth; ++i) {
      g1_mul_fix(g1s[1], &public_params->h_precomputation_tables[i * RLC_EP_TABLE],
                 identity_zp_vector[i]);
      g1_add(g1s[0], g1s[0], g1s[1]);
    }

    g1_mul_fix(g1s[1], &public_params->h_precomputation_tables[identity->depth * RLC_EP_TABLE], u);
    g1_add(g1s[0], g1s[0], g1s[1]);

    g1_mul_sim(g1s[1], g1s[0], w, secret_key->b[0], u);
    g1_add(g1s[1], secret_key->a0, g1s[1]);
    g1_neg(g1s[1], g1s[1]);
    g2_copy(g2s[1], ciphertext->b);

    g1_copy(g1s[0], ciphertext->c);
    g2_mul(g2s[0], public_params->g_hat, w);
    g2_add(g2s[0], g2s[0], secret_key->a1);

    pc_map_sim(key->k, g1s, g2s, 2);
    gt_mul(key->k, key->k, ciphertext->a);
  }
  CATCH_ANY {
    result_status = BFE_ERROR;
  }
  FINALLY {
    g2_free(g2s[1]);
    g2_free(g2s[0]);
    g1_free(g1s[1]);
    g1_free(g1s[0]);
    bn_free(w);
    bn_free(u);
  }

clear:
  for (size_t i = 0; i < identity->depth; ++i) {
    bn_free(identity_zp_vector[i]);
  }
  free(identity_zp_vector);
  return result_status;
}

static int ots_keygen(bbg_ots_sk_t* secret_key, bbg_ots_pk_t* public_key,
                      bbg_public_params_t* public_params) {
  int result_status = BFE_SUCCESS;

  TRY {
    // Choose a random s, x_s, y_s, r_s, s_s from Z_p^*.
    zp_rand(secret_key->xs);
    zp_rand(secret_key->ys);
    zp_rand(secret_key->rs);
    zp_rand(secret_key->ss);

    // Compute the OTS public key.
    g1_mul(public_key->fs, public_params->g, secret_key->xs);
    g1_mul(public_key->hs, public_params->g, secret_key->ys);
    g1_mul_sim(public_key->cs, public_key->fs, secret_key->rs, public_key->hs, secret_key->ss);
  }
  CATCH_ANY {
    result_status = BFE_ERROR;
  }

  return result_status;
}

static int ots_sign(bbg_ots_t* ots, vector_t* ciphertexts, bbg_ots_sk_t* ots_sk) {
  int result_status = BFE_SUCCESS;

  bn_t ciphertext_hash;
  bn_t tmp;
  bn_null(ciphertext_hash);
  bn_null(tmp);

  TRY {
    bn_new(ciphertext_hash);
    bn_new(tmp);

    Keccak_HashInstance ctx;
    Keccak_HashInitialize_SHAKE256(&ctx);
    Keccak_HashUpdate(&ctx, &SIGNATURE_PREFIX, sizeof(SIGNATURE_PREFIX) * 8);
    hash_update_bbg_ciphertexts(&ctx, ciphertexts);
    Keccak_HashFinal(&ctx, NULL);
    hash_squeeze_zp(ciphertext_hash, &ctx);

    zp_rand(ots->r);
    zp_sub(tmp, ots_sk->rs, ots->r);
    zp_mul(ots->s, ots_sk->xs, tmp);
    zp_mul(tmp, ots_sk->ys, ots_sk->ss);
    zp_add(ots->s, ots->s, tmp);
    zp_sub(tmp, ots->s, ciphertext_hash);
    zp_div(ots->s, tmp, ots_sk->ys);
  }
  CATCH_ANY {
    result_status = BFE_ERROR;
  }
  FINALLY {
    bn_free(tmp);
    bn_free(ciphertext_hash);
  }

  return result_status;
}

static int ots_verify(vector_t* ciphertexts, bbg_ots_t* ots, bbg_ots_pk_t* ots_pk,
                      bbg_public_params_t* public_params) {
  int result_status = BFE_SUCCESS;

  bn_t ciphertext_hash;
  bn_null(ciphertext_hash);

  g1_t tmp1;
  g1_t tmp2;
  g1_null(tmp1);
  g1_null(tmp2);

  TRY {
    bn_new(ciphertext_hash);

    g1_new(tmp1);
    g1_new(tmp2);

    Keccak_HashInstance ctx;
    Keccak_HashInitialize_SHAKE256(&ctx);
    Keccak_HashUpdate(&ctx, &SIGNATURE_PREFIX, sizeof(SIGNATURE_PREFIX) * 8);
    hash_update_bbg_ciphertexts(&ctx, ciphertexts);
    Keccak_HashFinal(&ctx, NULL);
    hash_squeeze_zp(ciphertext_hash, &ctx);

    g1_mul(tmp2, public_params->g, ciphertext_hash);
    g1_mul_sim(tmp1, ots_pk->fs, ots->r, ots_pk->hs, ots->s);
    g1_add(tmp1, tmp1, tmp2);
    if (g1_cmp(ots_pk->cs, tmp1) != RLC_EQ) {
      result_status = BFE_ERROR;
    }
  }
  CATCH_ANY {
    result_status = BFE_ERROR;
  }
  FINALLY {
    g1_free(tmp2);
    g1_free(tmp1);

    bn_free(ciphertext_hash);
  }

  return result_status;
}

static int bbg_convert_key_to_bit_string(uint8_t* bit_string, bbg_key_t* key) {
  int result_status = BFE_SUCCESS;
  TRY {
    // Hash binary represented bit string.
    uint8_t serialized_key[GT_SIZE_COMPRESSED];
    gt_write_bin(serialized_key, GT_SIZE_COMPRESSED, key->k, 1);
    md_kdf(bit_string, SECURITY_PARAMETER, serialized_key, GT_SIZE_COMPRESSED);
  }
  CATCH_ANY {
    result_status = BFE_ERROR;
  }
  FINALLY {}

  return result_status;
}

static void bbg_serialize_public_params(uint8_t* serialized, bbg_public_params_t* public_params) {
  write_u32(&serialized, public_params->max_delegatable_depth);
  write_g1(&serialized, public_params->g);
  write_g2(&serialized, public_params->g_hat);
  write_g1(&serialized, public_params->g2);
  write_g1(&serialized, public_params->g3);

  for (size_t i = 0; i < public_params->max_delegatable_depth + 1; ++i) {
    write_g1(&serialized, public_params->h[i]);
  }
}

static void bbg_serialize_public_key(uint8_t* serialized, bbg_public_key_t* public_key) {
  write_gt(&serialized, public_key->pk);
}

static void bbg_deserialize_public_key(bbg_public_key_t* public_key, const uint8_t* serialized) {
  read_gt(public_key->pk, &serialized);
}

static void bbg_serialize_identity(uint8_t* dst, const bbg_identity_t* identity) {
  write_u32(&dst, identity->depth);
  for (size_t i = 0; i < identity->depth; ++i) {
    write_u32(&dst, identity->id[i]);
  }
}

static void bbg_deserialize_identity(bbg_identity_t* identity, const uint8_t* src) {
  identity->depth = read_u32(&src);
  if (identity->id) {
    free(identity->id);
  }
  // TODO: add error check
  identity->id = calloc(identity->depth, sizeof(identity->id[0]));
  for (size_t i = 0; i < identity->depth; ++i) {
    identity->id[i] = read_u32(&src);
  }
}

static void bbg_serialize_secret_key(uint8_t* serialized, bbg_secret_key_t* secret_key) {
  write_u32(&serialized, secret_key->num_delegatable_levels);
  bbg_serialize_identity(serialized, &secret_key->identity);
  serialized += bbg_get_identity_size(&secret_key->identity);

  write_g1(&serialized, secret_key->a0);
  write_g2(&serialized, secret_key->a1);
  write_g1(&serialized, secret_key->associated_id);

  for (size_t i = 0; i < secret_key->num_delegatable_levels; ++i) {
    write_g1(&serialized, secret_key->b[i]);
  }
}

static void bbg_deserialize_secret_key(bbg_secret_key_t* secret_key, const uint8_t* serialized) {
  unsigned int num_delegatable_levels = read_u32(&serialized);
  bbg_init_secret_key(secret_key, num_delegatable_levels, 0);

  bbg_deserialize_identity(&secret_key->identity, serialized);
  serialized += bbg_get_identity_size(&secret_key->identity);

  read_g1(secret_key->a0, &serialized);
  read_g2(secret_key->a1, &serialized);
  read_g1(secret_key->associated_id, &serialized);

  for (size_t i = 0; i < num_delegatable_levels; ++i) {
    read_g1(secret_key->b[i], &serialized);
  }
}

static unsigned bbg_get_secret_key_size(const bbg_secret_key_t* secret_key) {
  return G1_SIZE_COMPRESSED + G2_SIZE_COMPRESSED + G1_SIZE_COMPRESSED + sizeof(uint32_t) +
         (secret_key->num_delegatable_levels * G1_SIZE_COMPRESSED) +
         bbg_get_identity_size(&secret_key->identity);
}

static unsigned bbg_get_public_params_size(const bbg_public_params_t* public_params) {
  return G2_SIZE_COMPRESSED + 3 * G1_SIZE_COMPRESSED + sizeof(uint32_t) +
         (public_params->max_delegatable_depth + 1) * G1_SIZE_COMPRESSED;
}

static int bbg_init_identity_from(bbg_identity_t* dst, unsigned int depth,
                                  const bbg_identity_t* src) {
  if (src == NULL) {
    return BFE_ERROR;
  }

  int ret = bbg_init_identity(dst, depth);
  if (ret != BFE_SUCCESS) {
    return ret;
  }

  memcpy(dst->id, src->id, sizeof(dst->id[0]) * MIN(dst->depth, src->depth));
  return BFE_SUCCESS;
}

static void tbfe_bbg_vector_secret_key_free(vector_t* vector_secret_key) {
  for (size_t i = 0; i < vector_size(vector_secret_key); ++i) {
    bbg_secret_key_t* sk = vector_get(vector_secret_key, i);
    bbg_clear_secret_key(sk);
    free(sk);
  }
  vector_free(vector_secret_key);
}

static int generate_zero_identity_with_last_component(bbg_identity_t* identity, unsigned int depth,
                                                      unsigned int last_component) {
  int ret = bbg_init_identity(identity, depth);
  if (!ret) {
    memset(identity->id, 0, sizeof(identity->id[0]) * (depth - 1));
    identity->id[depth - 1] = last_component;
  }
  return ret;
}

static inline unsigned long compute_tree_size(const unsigned h) {
  return (2ul << h) - 1;
}

int tbfe_bbg_init_public_key(tbfe_bbg_public_key_t* public_key, unsigned int total_depth) {
  if (!public_key) {
    return BFE_ERROR_INVALID_PARAM;
  }

  public_key->bloom_filter_hashes = 0;
  public_key->bloom_filter_size   = 0;

  if (bbg_init_public_key(&public_key->pk) != BFE_SUCCESS ||
      bbg_init_public_params(&public_key->params, total_depth) != BFE_SUCCESS) {
    return BFE_ERROR;
  }

  return BFE_SUCCESS;
}

int tbfe_bbg_init_public_key_from_serialized(tbfe_bbg_public_key_t* public_key,
                                             const uint8_t* src) {
  if (!public_key || !src) {
    return BFE_ERROR_INVALID_PARAM;
  }

  public_key->bloom_filter_hashes = read_u32(&src);
  public_key->bloom_filter_size   = read_u32(&src);

  if (bbg_init_public_key(&public_key->pk) != BFE_SUCCESS) {
    return BFE_ERROR;
  }
  // FIXME: add error code and handle errors
  bbg_deserialize_public_key(&public_key->pk, src);
  src += BBG_PUBLIC_KEY_SIZE;

  return bbg_init_public_params_from_serialized(&public_key->params, src);
}

void tbfe_bbg_clear_public_key(tbfe_bbg_public_key_t* public_key) {
  if (public_key) {
    bbg_clear_public_params(&public_key->params);
    bbg_clear_public_key(&public_key->pk);
  }
}

int tbfe_bbg_init_secret_key(tbfe_bbg_secret_key_t* secret_key, unsigned int bloom_filter_size,
                             double false_positive_prob) {
  if (!secret_key) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int err = BFE_SUCCESS;

  secret_key->bloom_filter = bf_init(bloom_filter_size, false_positive_prob);
  omp_init_lock(&secret_key->bloom_filter_mutex);
  secret_key->sk_bloom      = vector_new(bloom_filter_size);
  secret_key->sk_time       = vector_new(3);
  secret_key->next_interval = 1;

  return err;
}

int tbfe_bbg_init_secret_key_from_serialized(tbfe_bbg_secret_key_t* secret_key,
                                             const uint8_t* src) {
  if (!secret_key || !src) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int err = BFE_SUCCESS;

  omp_init_lock(&secret_key->bloom_filter_mutex);

  const unsigned int sk_bloom_count = read_u32(&src);
  const unsigned int sk_time_count  = read_u32(&src);
  secret_key->next_interval         = read_u32(&src);

  const unsigned int hash_count  = read_u32(&src);
  const unsigned int filter_size = read_u32(&src);

  secret_key->bloom_filter = bf_init_fixed(filter_size, hash_count);
  for (unsigned int i = 0; i < BITSET_SIZE(secret_key->bloom_filter.bitset.size); ++i) {
    secret_key->bloom_filter.bitset.bits[i] = read_u64(&src);
  }

  secret_key->sk_bloom = vector_new(sk_bloom_count);
  secret_key->sk_time  = vector_new(sk_time_count);

  for (size_t i = 0; i < sk_bloom_count; ++i) {
    const unsigned int sk_size = read_u32(&src);
    if (!sk_size) {
      vector_add(secret_key->sk_bloom, NULL);
    } else {
      bbg_secret_key_t* sk_bloom_i = malloc(sizeof(*sk_bloom_i));
      bbg_deserialize_secret_key(sk_bloom_i, src);
      src += sk_size;
      vector_add(secret_key->sk_bloom, sk_bloom_i);
    }
  }

  for (size_t i = 0; i < sk_time_count; ++i) {
    const unsigned int sk_size  = read_u32(&src);
    bbg_secret_key_t* sk_time_i = malloc(sizeof(*sk_time_i));
    bbg_deserialize_secret_key(sk_time_i, src);
    src += sk_size;
    vector_add(secret_key->sk_time, sk_time_i);
  }

  return err;
}

void tbfe_bbg_clear_secret_key(tbfe_bbg_secret_key_t* secret_key) {
  if (secret_key) {
    tbfe_bbg_vector_secret_key_free(secret_key->sk_bloom);
    tbfe_bbg_vector_secret_key_free(secret_key->sk_time);

    bf_clear(&secret_key->bloom_filter);
    omp_destroy_lock(&secret_key->bloom_filter_mutex);
    secret_key->next_interval = 0;
  }
}

int tbfe_bbg_init_ciphertext(tbfe_bbg_ciphertext_t* ciphertext) {
  if (!ciphertext) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int ret = BFE_SUCCESS;

  ciphertext->Cs            = vector_new(0);
  ciphertext->time_interval = 0;
  if (bbg_init_ots(&ciphertext->ots) != BFE_SUCCESS ||
      bbg_init_ots_public_key(&ciphertext->ots_pk) != BFE_SUCCESS) {
    ret = BFE_ERROR;
  }

  return ret;
}

int tbfe_bbg_init_ciphertext_from_serialized(tbfe_bbg_ciphertext_t* ciphertext,
                                             const uint8_t* src) {
  if (!ciphertext || !src) {
    return BFE_ERROR_INVALID_PARAM;
  }

  unsigned int ciphertext_count = read_u32(&src);

  if (bbg_init_ots(&ciphertext->ots) != BFE_SUCCESS ||
      bbg_init_ots_public_key(&ciphertext->ots_pk) != BFE_SUCCESS) {
    return BFE_ERROR;
  }

  ciphertext->time_interval = read_u32(&src);
  ciphertext->Cs            = vector_new(ciphertext_count);
  for (size_t i = 0; i < ciphertext_count; ++i) {
    bbg_ciphertext_t* ct_i = malloc(sizeof(*ct_i));
    if (!ct_i || bbg_init_ciphertext(ct_i) != BFE_SUCCESS) {
      bbg_clear_ciphertext(ct_i);
      free(ct_i);
      return BFE_ERROR;
    }

    bbg_deserialize_ciphertext(ct_i, src);
    src += BBG_CIPHERTEXT_SIZE;
    vector_add(ciphertext->Cs, ct_i);
  }

  memcpy(ciphertext->c, src, SECURITY_PARAMETER);
  src += SECURITY_PARAMETER;

  read_bn(ciphertext->ots.r, &src);
  read_bn(ciphertext->ots.s, &src);
  read_g1(ciphertext->ots_pk.fs, &src);
  read_g1(ciphertext->ots_pk.hs, &src);
  read_g1(ciphertext->ots_pk.cs, &src);

  return BFE_SUCCESS;
}

void tbfe_bbg_clear_ciphertext(tbfe_bbg_ciphertext_t* ciphertext) {
  if (ciphertext) {
    for (size_t idx = 0; idx < vector_size(ciphertext->Cs); ++idx) {
      bbg_ciphertext_t* ct = vector_get(ciphertext->Cs, idx);
      bbg_clear_ciphertext(ct);
      free(ct);
    }
    bbg_clear_ots_public_key(&ciphertext->ots_pk);
    bbg_clear_ots(&ciphertext->ots);
    vector_free(ciphertext->Cs);
  }
}

static int tbfe_bbg_index_to_identity(bbg_identity_t* identity, const unsigned long index,
                                      const unsigned height) {
  if (!identity || index >= compute_tree_size(height)) {
    return BFE_ERROR_INVALID_PARAM;
  }

  uint8_t* buffer = malloc(height * sizeof(*buffer));
  if (!buffer) {
    return BFE_ERROR;
  }

  unsigned long node_count = 0;
  size_t length            = 0;

  for (size_t level = 0; level < height; ++level) {
    unsigned long subtree_height = compute_tree_size(height - level - 1);
    if (node_count == index) {
      break;
    } else if (index <= (subtree_height + node_count)) {
      buffer[length++] = 0;
      ++node_count;
    } else {
      buffer[length++] = 1;
      node_count += subtree_height + 1;
    }
  }

  const int ret = bbg_init_identity(identity, length);
  if (ret) {
    goto clear_buffer;
  }

  for (size_t i = 0; i < length; ++i) {
    identity->id[i] = buffer[i];
  }

clear_buffer:
  free(buffer);
  return ret;
}

void tbfe_bbg_serialize_public_key(uint8_t* serialized, tbfe_bbg_public_key_t* public_key) {
  write_u32(&serialized, public_key->bloom_filter_hashes);
  write_u32(&serialized, public_key->bloom_filter_size);

  bbg_serialize_public_key(serialized, &public_key->pk);
  serialized += BBG_PUBLIC_KEY_SIZE;
  bbg_serialize_public_params(serialized, &public_key->params);
}

void tbfe_bbg_serialize_secret_key(uint8_t* serialized, tbfe_bbg_secret_key_t* secret_key) {
  unsigned sk_bloom_count = vector_size(secret_key->sk_bloom);
  unsigned sk_time_count  = vector_size(secret_key->sk_time);

  write_u32(&serialized, sk_bloom_count);
  write_u32(&serialized, sk_time_count);
  write_u32(&serialized, secret_key->next_interval);

  write_u32(&serialized, secret_key->bloom_filter.hash_count);
  write_u32(&serialized, secret_key->bloom_filter.bitset.size);
  for (unsigned int i = 0; i < BITSET_SIZE(secret_key->bloom_filter.bitset.size); ++i) {
    write_u64(&serialized, secret_key->bloom_filter.bitset.bits[i]);
  }

  for (size_t i = 0; i < sk_bloom_count; ++i) {
    bbg_secret_key_t* sk_bloom_i = vector_get(secret_key->sk_bloom, i);
    if (sk_bloom_i == NULL) {
      write_u32(&serialized, 0);
    } else {
      const unsigned int sk_size = bbg_get_secret_key_size(sk_bloom_i);
      write_u32(&serialized, sk_size);
      bbg_serialize_secret_key(serialized, sk_bloom_i);
      serialized += sk_size;
    }
  }

  for (size_t i = 0; i < sk_time_count; ++i) {
    bbg_secret_key_t* sk_time_i   = vector_get(secret_key->sk_time, i);
    const unsigned sk_time_i_size = bbg_get_secret_key_size(sk_time_i);

    write_u32(&serialized, sk_time_i_size);
    bbg_serialize_secret_key(serialized, sk_time_i);
    serialized += sk_time_i_size;
  }
}

void tbfe_bbg_serialize_ciphertext(uint8_t* serialized, tbfe_bbg_ciphertext_t* ciphertext) {
  const unsigned ciphertext_count = vector_size(ciphertext->Cs);

  write_u32(&serialized, ciphertext_count);
  write_u32(&serialized, ciphertext->time_interval);
  for (size_t i = 0; i < ciphertext_count; ++i) {
    bbg_ciphertext_t* ct_i = vector_get(ciphertext->Cs, i);
    bbg_serialize_ciphertext(serialized, ct_i);
    serialized += BBG_CIPHERTEXT_SIZE;
  }

  memcpy(serialized, ciphertext->c, SECURITY_PARAMETER);
  serialized += SECURITY_PARAMETER;

  write_bn(&serialized, ciphertext->ots.r);
  write_bn(&serialized, ciphertext->ots.s);
  write_g1(&serialized, ciphertext->ots_pk.fs);
  write_g1(&serialized, ciphertext->ots_pk.hs);
  write_g1(&serialized, ciphertext->ots_pk.cs);
}

unsigned tbfe_bbg_get_public_key_size(const tbfe_bbg_public_key_t* public_key) {
  return BBG_PUBLIC_KEY_SIZE + bbg_get_public_params_size(&public_key->params) +
         2 * sizeof(uint32_t);
}

unsigned tbfe_bbg_get_secret_key_size(const tbfe_bbg_secret_key_t* secret_key) {
  unsigned int sk_bloom_count = vector_size(secret_key->sk_bloom);
  unsigned int sk_time_count  = vector_size(secret_key->sk_time);

  unsigned int total_size =
      5 * sizeof(uint32_t) + BITSET_SIZE(secret_key->bloom_filter.bitset.size) * sizeof(uint64_t);
  for (size_t i = 0; i < sk_bloom_count; ++i) {
    bbg_secret_key_t* sk_bloom_i = vector_get(secret_key->sk_bloom, i);
    if (sk_bloom_i != NULL) {
      total_size += bbg_get_secret_key_size(sk_bloom_i);
    }
    total_size += sizeof(uint32_t);
  }
  for (size_t i = 0; i < sk_time_count; ++i) {
    bbg_secret_key_t* sk_time_i = vector_get(secret_key->sk_time, i);
    total_size += bbg_get_secret_key_size(sk_time_i) + sizeof(uint32_t);
  }
  return total_size;
}

unsigned tbfe_bbg_get_ciphertext_size(const tbfe_bbg_ciphertext_t* ciphertext) {
  const unsigned ciphertext_count = vector_size(ciphertext->Cs);
  return 2 * sizeof(uint32_t) + (ciphertext_count * BBG_CIPHERTEXT_SIZE) + SECURITY_PARAMETER +
         OTS_SIZE + OTS_PUBLIC_KEY_SIZE;
}

static int derive_key_and_add(vector_t* dst, bbg_public_params_t* params, bbg_master_key_t* msk,
                              const bbg_identity_t* identity, unsigned int total_depth) {
  bbg_secret_key_t* sk = malloc(sizeof(*sk));
  if (!sk) {
    return BFE_ERROR;
  }

  int ret = bbg_init_secret_key(sk, total_depth - identity->depth, identity->depth);
  if (ret) {
    goto error;
  }

  ret = bbg_key_generation_from_master_key(sk, msk, identity, params);
  if (ret) {
    goto error;
  }

  if (vector_add(dst, sk)) {
    ret = BFE_ERROR;
    goto error;
  }
  return BFE_SUCCESS;

error:
  bbg_clear_secret_key(sk);
  free(sk);
  return ret;
}

int tbfe_bbg_keygen(tbfe_bbg_public_key_t* public_key, tbfe_bbg_secret_key_t* secret_key) {
  if (!public_key || !secret_key || !secret_key->bloom_filter.bitset.size ||
      public_key->params.max_delegatable_depth < 2) {
    return BFE_ERROR_INVALID_PARAM;
  }

  bbg_master_key_t msk;
  int result_status = bbg_init_master_key(&msk);
  if (result_status) {
    goto clear;
  }

  const unsigned int total_levels          = public_key->params.max_delegatable_depth - 1;
  const unsigned int number_hash_functions = secret_key->bloom_filter.hash_count;
  const unsigned int bloom_filter_size     = secret_key->bloom_filter.bitset.size;

  // We want to have a t + 1 level HIBE, but due to CHK compiler approach
  // used in the CCA secure variant of BBG-HIBE, we need to setup with t + 2.
  const unsigned total_depth = total_levels + 2;
  secret_key->next_interval  = 1;

  // Generate master secret key and public key for BBG HIBE scheme.
  result_status = bbg_setup(&msk, &public_key->pk, &public_key->params, total_depth);
  if (result_status) {
    goto clear;
  }

#pragma omp parallel reduction(| : result_status)
  {
    int ret = BFE_SUCCESS;

    // Private vector for each thread to store the generated secret keys.
    vector_t secret_key_private = {NULL, 0, 0};
    if (vector_init(&secret_key_private, secret_key->sk_bloom->capacity / omp_get_num_threads())) {
      ret = BFE_ERROR;
      goto clear_thread;
    }

    // For each identity in [0, bloom_filter_size - 1] extract a secret key.
    // Static scheduling ensures that each thread is assigned one consecutive chunk of loop
    // iterations.
#pragma omp for schedule(static)
    for (unsigned identity = 0; identity < bloom_filter_size; ++identity) {
      // Generate the identities 0|0, 0|1, 0|2, ..., 0|m-1.
      bbg_identity_t identity_0i;
      ret |= generate_zero_identity_with_last_component(&identity_0i, 2, identity);
      if (ret) {
        goto clear_loop;
      }

      ret |= derive_key_and_add(&secret_key_private, &public_key->params, &msk, &identity_0i,
                                total_depth);
    clear_loop:
      bbg_clear_identity(&identity_0i);
    }

    // Copy the generated secret keys from the private vectors of the threads.
    // Executing the loop ordered ensures that the secret keys are added in increasing order of
    // identities.
#pragma omp for ordered
    for (int i = 0; i < omp_get_num_threads(); ++i) {
#pragma omp ordered
      vector_copy(secret_key->sk_bloom, &secret_key_private);
    }

  clear_thread:
    vector_clear(&secret_key_private);
    result_status |= ret;
  }

  if (result_status) {
    goto clear;
  }

  // Puncture sk_0 and compute keys for its children (00, 01) and for identity 1.
  bbg_identity_t identity_1;
  bbg_identity_t identity_00;
  bbg_identity_t identity_01;

  result_status = bbg_init_identity(&identity_1, 1);
  if (result_status) {
    goto clear_identities_1;
  }
  identity_1.id[0] = 1;

  result_status = generate_zero_identity_with_last_component(&identity_00, 2, 0);
  if (result_status) {
    goto clear_identities_00;
  }
  result_status = generate_zero_identity_with_last_component(&identity_01, 2, 1);
  if (result_status) {
    goto clear_identities_01;
  }

  if ((result_status = derive_key_and_add(secret_key->sk_time, &public_key->params, &msk,
                                          &identity_1, total_depth)) ||
      (result_status = derive_key_and_add(secret_key->sk_time, &public_key->params, &msk,
                                          &identity_00, total_depth)) ||
      (result_status = derive_key_and_add(secret_key->sk_time, &public_key->params, &msk,
                                          &identity_01, total_depth))) {
    goto clear_identities_01;
  }

  ++secret_key->next_interval;
  public_key->bloom_filter_hashes = number_hash_functions;
  public_key->bloom_filter_size   = bloom_filter_size;

clear_identities_01:
  bbg_clear_identity(&identity_01);
clear_identities_00:
  bbg_clear_identity(&identity_00);
clear_identities_1:
  bbg_clear_identity(&identity_1);
clear:
  bbg_clear_master_key(&msk);
  return result_status;
}

int tbfe_bbg_encaps(uint8_t* key, tbfe_bbg_ciphertext_t* ciphertext,
                    tbfe_bbg_public_key_t* public_key, unsigned int time_interval) {
  if (!ciphertext || !public_key) {
    return BFE_ERROR_INVALID_PARAM;
  }

  bbg_identity_t tau = {0, NULL};
  int result_status =
      tbfe_bbg_index_to_identity(&tau, time_interval, public_key->params.max_delegatable_depth - 1);
  if (result_status) {
    goto clear_tau;
  }

  // Generate the all tau plus bloom identity.
  const unsigned tau_i_depth = tau.depth + 1;
  bbg_identity_t identity_tau_i;
  result_status = bbg_init_identity_from(&identity_tau_i, tau_i_depth, &tau);
  if (result_status) {
    goto clear_identity_tau_i;
  }

  bbg_ots_sk_t ots_sk;
  result_status = ots_init_sk(&ots_sk);
  if (result_status) {
    goto clear_ots_sk;
  }
  result_status = ots_keygen(&ots_sk, &ciphertext->ots_pk, &public_key->params);
  if (result_status) {
    goto clear_ots_sk;
  }

  bbg_key_t _key;
  result_status = bbg_init_key(&_key);
  if (result_status) {
    goto clear;
  }

  result_status = bbg_sample_key(&_key);
  if (result_status) {
    goto clear;
  }

  // Generate random c.
  rand_bytes(ciphertext->c, SECURITY_PARAMETER);

  const unsigned int k = public_key->bloom_filter_hashes;
  // Derive the identities from the random c with the hash functions of the bloom filter.
  for (size_t i = 0; i < k; ++i) {
    identity_tau_i.id[tau_i_depth - 1] =
        bf_get_position(i, ciphertext->c, SECURITY_PARAMETER, public_key->bloom_filter_size);

    bbg_ciphertext_t* ct = malloc(sizeof(*ct));
    result_status        = bbg_init_ciphertext(ct);
    if (result_status) {
      goto clear_ciphertext;
    }

    result_status = bbg_encapsulate(ct, _key.k, &public_key->pk, &ciphertext->ots_pk,
                                    &public_key->params, &identity_tau_i);
    if (result_status) {
      goto clear_ciphertext;
    }

    if (vector_add(ciphertext->Cs, ct)) {
      result_status = BFE_ERROR;
      goto clear_ciphertext;
    }
    continue;

  clear_ciphertext:
    bbg_clear_ciphertext(ct);
    free(ct);
    goto clear;
  }

  result_status = ots_sign(&ciphertext->ots, ciphertext->Cs, &ots_sk);
  if (result_status) {
    goto clear;
  }

  ciphertext->time_interval = time_interval;
  // Convert the key generated by BBG HIBE scheme into a bit string.
  result_status = bbg_convert_key_to_bit_string(key, &_key);

clear:
  bbg_clear_key(&_key);
clear_ots_sk:
  ots_clear_sk(&ots_sk);
clear_identity_tau_i:
  bbg_clear_identity(&identity_tau_i);
clear_tau:
  bbg_clear_identity(&tau);
  return result_status;
}

int tbfe_bbg_decaps(uint8_t* key, tbfe_bbg_ciphertext_t* ciphertext,
                    tbfe_bbg_secret_key_t* secret_key, tbfe_bbg_public_key_t* public_key) {
  if (!key || !ciphertext || !secret_key || !public_key) {
    return BFE_ERROR_INVALID_PARAM;
  }

  if (secret_key->next_interval - 1 != ciphertext->time_interval) {
    return BFE_ERROR;
  }

  bbg_identity_t tau = {0, NULL};
  int result_status  = tbfe_bbg_index_to_identity(&tau, secret_key->next_interval - 1,
                                                 public_key->params.max_delegatable_depth - 1);
  if (result_status) {
    result_status = BFE_ERROR;
    goto clear_tau;
  }

  // Generate the tau plus bloom identity.
  const unsigned int tau_i_depth = tau.depth + 1;
  bbg_identity_t tau_prime       = {0, NULL};
  result_status                  = bbg_init_identity_from(&tau_prime, tau_i_depth, &tau);
  if (result_status) {
    goto clear_tau_prime;
  }

  bbg_key_t _key;
  result_status = bbg_init_key(&_key);
  if (result_status) {
    goto clear_key;
  }

  omp_set_lock(&secret_key->bloom_filter_mutex);

  int decapsulating_identity_index = -1;
  unsigned decapsulating_identity  = 0;

  // Derive the identities under which this ciphertext was encapsulated and mark
  // the first identity for which the secret key has not been punctured yet.
  const unsigned k = secret_key->bloom_filter.hash_count;
  for (size_t i = 0; i < k; ++i) {
    const unsigned int hash =
        bf_get_position(i, ciphertext->c, SECURITY_PARAMETER, secret_key->bloom_filter.bitset.size);
    if (bitset_get(&secret_key->bloom_filter.bitset, hash) == 0 &&
        vector_get(secret_key->sk_bloom, hash) != NULL) {
      decapsulating_identity_index  = i;
      decapsulating_identity        = hash;
      tau_prime.id[tau_i_depth - 1] = hash;
      break;
    }
  }

  // The ciphertext can not be decapsulated if all secret keys for which the
  // ciphertext was encapsulated are deleted. This is the case if check for
  // this c returns true. If it returns 0 there must be a secret key with
  // which the ciphertext can be decapsulated.
  if (decapsulating_identity_index == -1) {
    result_status = BFE_ERROR;
    goto clear;
  }

  bbg_secret_key_t* sk_id         = vector_get(secret_key->sk_bloom, decapsulating_identity);
  bbg_ciphertext_t* ciphertext_id = vector_get(ciphertext->Cs, decapsulating_identity_index);

  // Verify OTS signatures on the ciphertexts.
  result_status =
      ots_verify(ciphertext->Cs, &ciphertext->ots, &ciphertext->ots_pk, &public_key->params);
  if (result_status) {
    goto clear;
  }

  // Decapsulate the ciphertext to get the key.
  result_status = bbg_decapsulate(&_key, ciphertext_id, sk_id, &ciphertext->ots_pk,
                                  &public_key->params, &tau_prime);
  if (result_status) {
    // This case should never happen if we have a key
    goto clear;
  }

  // Convert the key from BBG HIBE scheme into a bit string.
  result_status = bbg_convert_key_to_bit_string(key, &_key);

clear:
  omp_unset_lock(&secret_key->bloom_filter_mutex);
clear_key:
  bbg_clear_key(&_key);
clear_tau_prime:
  bbg_clear_identity(&tau_prime);
clear_tau:
  bbg_clear_identity(&tau);
  return result_status;
}

int tbfe_bbg_puncture_ciphertext(tbfe_bbg_secret_key_t* secret_key,
                                 tbfe_bbg_ciphertext_t* ciphertext) {
  if (!secret_key || !ciphertext) {
    return BFE_ERROR_INVALID_PARAM;
  }

  omp_set_lock(&secret_key->bloom_filter_mutex);
  // Add c to the bloom filter.
  for (unsigned int i = 0; i < secret_key->bloom_filter.hash_count; ++i) {
    unsigned int pos =
        bf_get_position(i, ciphertext->c, SECURITY_PARAMETER, secret_key->bloom_filter.bitset.size);
    bitset_set(&secret_key->bloom_filter.bitset, pos);

    bbg_secret_key_t* sk = vector_get(secret_key->sk_bloom, pos);
    if (sk) {
      bbg_clear_secret_key(sk);
      free(sk);
      vector_set(secret_key->sk_bloom, pos, NULL);
    }
  }

  omp_unset_lock(&secret_key->bloom_filter_mutex);
  return BFE_SUCCESS;
}

static int puncture_derive_key_and_add(vector_t* dst, bbg_public_params_t* params,
                                       bbg_secret_key_t* sk, const bbg_identity_t* identity) {
  bbg_secret_key_t* sknew = malloc(sizeof(*sknew));
  if (!sknew) {
    return BFE_ERROR;
  }

  int ret = bbg_init_secret_key(sknew, params->max_delegatable_depth + 1 - identity->depth,
                                identity->depth);
  if (ret) {
    goto clear;
  }

  ret = bbg_key_generation_from_parent(sknew, sk, identity, params);
  if (ret) {
    goto clear;
  }

  if (vector_add(dst, sknew)) {
    ret = BFE_ERROR;
    goto clear;
  }
  return ret;

clear:
  bbg_clear_secret_key(sknew);
  free(sknew);
  return ret;
}

int tbfe_bbg_puncture_interval(tbfe_bbg_secret_key_t* secret_key, tbfe_bbg_public_key_t* public_key,
                               unsigned int time_interval) {
  if (!secret_key || !public_key) {
    return BFE_ERROR_INVALID_PARAM;
  }

  bbg_identity_t tau   = {0, NULL};
  const unsigned int t = public_key->params.max_delegatable_depth - 1;
  int result_status    = tbfe_bbg_index_to_identity(&tau, time_interval, t);
  if (result_status) {
    goto clear_tau;
  }
  const unsigned tau_i_depth = tau.depth + 1;

  bbg_secret_key_t* sk_tau = NULL;
  // Get the secret key for new tau (sk_tau) from the keys in sk_time.
  for (size_t i = 0; !sk_tau && i < vector_size(secret_key->sk_time); ++i) {
    bbg_secret_key_t* sk_time_i = vector_get(secret_key->sk_time, i);
    if (bbg_identities_are_equal(&sk_time_i->identity, &tau)) {
      sk_tau = sk_time_i;
    }
  }
  if (!sk_tau) {
    result_status = BFE_ERROR;
    goto clear_tau;
  }

  // Reset the bloom filter.
  bf_reset(&secret_key->bloom_filter);

  // Clear the existing bloom filter keys, and generate new ones for
  // the time interval tau.
  const unsigned bloom_filter_size = public_key->bloom_filter_size;
  tbfe_bbg_vector_secret_key_free(secret_key->sk_bloom);
  secret_key->sk_bloom = vector_new(bloom_filter_size);
  if (!secret_key->sk_bloom) {
    result_status = BFE_ERROR;
    goto clear_tau;
  }

#pragma omp parallel reduction(| : result_status)
  {
    bbg_identity_t identity_tau_i;
    // Generate an identity to hold tau|i for i in [0,...,m].
    int ret = bbg_init_identity_from(&identity_tau_i, tau_i_depth, &tau);
    if (ret) {
      goto clear_identity_tau_i;
    }

    // Private vector for each thread to store the generated secret keys.
    vector_t secret_key_private = {NULL, 0, 0};
    if (vector_init(&secret_key_private, secret_key->sk_bloom->capacity / omp_get_num_threads())) {
      ret = BFE_ERROR;
      goto clear_thread;
    }

    // For each identity in [0, bloom_filter_size - 1] extract a secret key.
    // Static scheduling ensures that each thread is assigned one consecutive chunk of loop
    // iterations.
#pragma omp for schedule(static)
    for (unsigned identity = 0; identity < bloom_filter_size; ++identity) {
      // Generate the identities tau|0, tau|1, tau|2, ..., tau|m-1.
      identity_tau_i.id[tau_i_depth - 1] = identity;
      ret |= puncture_derive_key_and_add(&secret_key_private, &public_key->params, sk_tau,
                                         &identity_tau_i);
    }

    // Copy the generated secret keys from the private vectors of the threads.
    // Executing the loop ordered ensures that the secret keys are added in increasing order of
    // identities.
#pragma omp for ordered
    for (int i = 0; i < omp_get_num_threads(); ++i) {
#pragma omp ordered
      vector_copy(secret_key->sk_bloom, &secret_key_private);
    }

    result_status |= ret;

  clear_thread:
    vector_clear(&secret_key_private);
  clear_identity_tau_i:
    bbg_clear_identity(&identity_tau_i);
  }

  if (result_status) {
    goto clear_tau;
  }

  // We are not in the leaf of the tree, hence, we generate keys for its children.
  if (sk_tau->identity.depth < t) {
    bbg_identity_t identity_tau_i;
    result_status = bbg_init_identity_from(&identity_tau_i, tau_i_depth, &tau);
    if (result_status) {
      goto clear_leaf;
    }

    // Generate key for the left child.
    identity_tau_i.id[tau_i_depth - 1] = 0;
    result_status = puncture_derive_key_and_add(secret_key->sk_time, &public_key->params, sk_tau,
                                                &identity_tau_i);
    if (result_status) {
      goto clear_leaf;
    }

    identity_tau_i.id[tau_i_depth - 1] = 1;
    result_status = puncture_derive_key_and_add(secret_key->sk_time, &public_key->params, sk_tau,
                                                &identity_tau_i);

  clear_leaf:
    bbg_clear_identity(&identity_tau_i);
  }

  if (result_status) {
    goto clear_tau;
  }

  // Delete the current tau from sk_time.
  for (size_t i = 0; i < vector_size(secret_key->sk_time); ++i) {
    bbg_secret_key_t* sk_time_i = vector_get(secret_key->sk_time, i);
    if (bbg_identities_are_equal(&sk_time_i->identity, &tau)) {
      bbg_clear_secret_key(sk_time_i);
      free(sk_time_i);
      vector_delete(secret_key->sk_time, i);
      break;
    }
  }

  // Update the next interval.
  ++secret_key->next_interval;

clear_tau:
  bbg_clear_identity(&tau);
  return result_status;
}

#if defined(BFE_STATIC)
static bool bbg_public_keys_are_equal(bbg_public_key_t* l, bbg_public_key_t* r) {
  return gt_cmp(l->pk, r->pk) == RLC_EQ;
}

static bool bbg_public_params_are_equal(bbg_public_params_t* l, bbg_public_params_t* r) {
  if (g1_cmp(l->g, r->g) != RLC_EQ || g2_cmp(l->g_hat, r->g_hat) != RLC_EQ ||
      g1_cmp(l->g2, r->g2) != RLC_EQ || g1_cmp(l->g3, r->g3) != RLC_EQ ||
      l->max_delegatable_depth != r->max_delegatable_depth) {
    return false;
  }

  for (size_t i = 0; i < l->max_delegatable_depth; ++i) {
    if (g1_cmp(l->h[i], r->h[i]) != RLC_EQ) {
      return false;
    }
  }

  return true;
}

static bool bbg_secret_keys_are_equal(bbg_secret_key_t* l, bbg_secret_key_t* r) {
  if (!l && !r) {
    return true;
  }
  if (!l || !r) {
    return false;
  }

  if (g1_cmp(l->a0, r->a0) != RLC_EQ || g2_cmp(l->a1, r->a1) != RLC_EQ ||
      l->num_delegatable_levels != r->num_delegatable_levels ||
      g1_cmp(l->associated_id, r->associated_id) != RLC_EQ) {
    return false;
  }

  for (size_t i = 0; i < l->num_delegatable_levels; ++i) {
    if (g1_cmp(l->b[i], r->b[i]) != RLC_EQ) {
      return false;
    }
  }

  return bbg_identities_are_equal(&l->identity, &r->identity);
}

static bool bbg_ciphertexts_are_equal(bbg_ciphertext_t* l, bbg_ciphertext_t* r) {
  return gt_cmp(l->a, r->a) == RLC_EQ && g2_cmp(l->b, r->b) == RLC_EQ &&
         g1_cmp(l->c, r->c) == RLC_EQ;
}

bool tbfe_bbg_public_keys_are_equal(tbfe_bbg_public_key_t* l, tbfe_bbg_public_key_t* r) {
  return bbg_public_keys_are_equal(&l->pk, &r->pk) &&
         bbg_public_params_are_equal(&l->params, &r->params) &&
         l->bloom_filter_size == r->bloom_filter_size &&
         l->bloom_filter_hashes == r->bloom_filter_hashes;
}

bool tbfe_bbg_secret_keys_are_equal(tbfe_bbg_secret_key_t* l, tbfe_bbg_secret_key_t* r) {
  if (vector_size(l->sk_bloom) != vector_size(r->sk_bloom) ||
      l->bloom_filter.hash_count != r->bloom_filter.hash_count ||
      l->bloom_filter.bitset.size != r->bloom_filter.bitset.size) {
    return false;
  }

  const uint64_t* bitarray1 = l->bloom_filter.bitset.bits;
  const uint64_t* bitarray2 = r->bloom_filter.bitset.bits;
  if (memcmp(bitarray1, bitarray2, BITSET_SIZE(l->bloom_filter.bitset.size) * sizeof(uint64_t))) {
    return false;
  }

  for (size_t i = 0; i < vector_size(l->sk_bloom); ++i) {
    bbg_secret_key_t* sk_l = vector_get(l->sk_bloom, i);
    bbg_secret_key_t* sk_r = vector_get(r->sk_bloom, i);
    if (!bbg_secret_keys_are_equal(sk_l, sk_r)) {
      return false;
    }
  }

  for (size_t i = 0; i < vector_size(l->sk_time); ++i) {
    bbg_secret_key_t* sk_l = vector_get(l->sk_time, i);
    bbg_secret_key_t* sk_r = vector_get(r->sk_time, i);
    if (!bbg_secret_keys_are_equal(sk_l, sk_r)) {
      return false;
    }
  }

  return true;
}

bool tbfe_bbg_ciphertexts_are_equal(tbfe_bbg_ciphertext_t* l, tbfe_bbg_ciphertext_t* r) {
  if (memcmp(l->c, r->c, SECURITY_PARAMETER) || l->time_interval != r->time_interval) {
    return false;
  }

  const unsigned int ciphertext_size = vector_size(l->Cs);
  if (ciphertext_size != vector_size(r->Cs)) {
    return false;
  }

  for (size_t i = 0; i < ciphertext_size; ++i) {
    bbg_ciphertext_t* l_ct = vector_get(l->Cs, i);
    bbg_ciphertext_t* r_ct = vector_get(r->Cs, i);
    if (!bbg_ciphertexts_are_equal(l_ct, r_ct)) {
      return false;
    }
  }

  return true;
}
#endif
