/*
 * This file contains the implementation of the TBFE scheme.
 * BBG HIBE is used for key delegation in a binary tree structure.
 * Forward secrecy is achieved by puncturing the secret key for specific ciphertexts (via bloom
 * filter) or after some time interval (via tree).
 *
 * The implementation utilizes EVERY node (in the tree) as distinct time interval (not only the
 * leaves). Index-To-Identity mapping is done via indexing the nodes in a 'pre-order traversal'
 * manner.
 *
 * To achieche CCA security the CHK compiler is added as additional layer to the HIBE.
 *
 */

/*
 * The code contains different definitions of the tree height (or depth), which are explained here:
 *  - max_delegatable_depth   : Number of levels for key delegation (includes bloom filter keys).
 *  - total_depth             : Height of the tree including bloom filter keys and CHK signature -->
 * equal to 'max_delegatable_depth + 1'.
 *
 * Following definitions are used together with some specific identity ID at depth d.
 *  - num_delegatable_levels  : Number of levels for further key delegation of subtree with ID as
 * root --> equal to 'total_depth - ID.depth'. This variable refers to the number of b_i (basis)
 * elements as part of some BBG secret key (cmp. BBG HIBE key generation).
 */

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

// ##################################################
// ##### ADDITIONAL STRUCTS AND DEFINES FOR BBG #####
// ##################################################

/* BBG ciphertext consists of three group elemnts */
#define BBG_CIPHERTEXT_SIZE (G1_SIZE_COMPRESSED + G2_SIZE_COMPRESSED + GT_SIZE_COMPRESSED)
/* BBG publick key consists of one group element*/
#define BBG_PUBLIC_KEY_SIZE GT_SIZE_COMPRESSED

/**
 * Represents a BBG HIBE identity in the tree.
 * An identity is defined by the its depth in the tree and the corresponding 0/1 (left/right child)
 * path from the root.
 */
typedef struct {
  unsigned depth; /**< Depth of the identity or distance from root. */
  unsigned* id;   /**< Array which uniquely defines the identity as a path from root. */
} bbg_identity_t;

/**
 * Generated symmetric Key which is encapsulated and shared by this protocol.
 */
typedef struct {
  gt_t k; /**< The key is represented by a G_t group element. */
} bbg_key_t;

/**
 * Represents a BBG HIBE master key.
 */
typedef struct {
  g1_t mk; /**< The master key is represented by a G_1 group element. */
} bbg_master_key_t;

/**
 * Secret key of BBG HIBE (cmp. with BBG HIBE key generation)
 * sk = [a0, a1, b_{k+1} ... b_l] where:
 *    - a0 = g_2^alpha * (h_1^I_1 * ... * h_k^I_k * g_3)^r
 *    - a1 = g^r
 *    - b  = [h_k^r, ..., h_l^r]
 */
typedef struct {
  unsigned num_delegatable_levels; /**< Number of elements in array b */
  bbg_identity_t identity; /**< Identity (or node of the tree) corresponding to the secret key */
  g1_t a0;                 /**< a0 part of the secret key - G_1 element */
  g2_t a1;                 /**< a1 part of the secret key - G_2 element */
  g1_t* b;                 /**< b_k to b_l of the secret key - G_1 elements*/
  g1_t associated_id; /**< This field stores the product (g_3 * h_1^I_1 * h_2^I_2 * ... * h_k^I_k)
                         for further key delegation. */
} bbg_secret_key_t;

/**
 * Ciphertext of BBG HIBE.
 * C = [a,b,c] where:
 *    - a = e(g_2, g_1)^s * M
 *    - b = g^s
 *    - c =(h_1^I_1 * ... * h_k^I_k * g_3)^s
 */
typedef struct {
  gt_t a; /**< a part of the ciphertext - G_t element */
  g2_t b; /**< b part of the ciphertext - G_2 element */
  g1_t c; /**< c part of the ciphertext - G_1 element */
} bbg_ciphertext_t;

/* Prefixes for hash function to achieve domain separation */
static const uint8_t IDENTITY_PREFIX     = 2;
static const uint8_t SIGNATURE_PREFIX    = 3;
static const uint8_t VERIFICATION_PREFIX = 4;

// ##################################################
// ############## FUNCTION PROTOTYPES ###############
// ##################################################

// OpenSSL EdDSA Signatures
static void eddsa_clear_sk(eddsa_sk_t* eddsa_sk);
static void eddsa_clear_pk(eddsa_pk_t* eddsa_pk);
static void eddsa_clear_sig(eddsa_sig_t* eddsa);
static int eddsa_keygen(eddsa_sk_t* eddsa_sk, eddsa_pk_t* eddsa_pk);
static int eddsa_sign(eddsa_sig_t* eddsa, vector_t* ciphertexts, eddsa_sk_t* eddsa_sk,
                      tbfe_bbg_public_key_t* pk);
static int eddsa_verify(vector_t* ciphertexts, eddsa_sig_t* eddsa, eddsa_pk_t* eddsa_pk,
                        tbfe_bbg_public_key_t* pk);
// ## SIZE
static unsigned int bbg_get_identity_size(const bbg_identity_t* identity);
static unsigned bbg_get_secret_key_size(const bbg_secret_key_t* secret_key);
static unsigned bbg_get_public_params_size(const bbg_public_params_t* public_params);
// ## INIT
static int bbg_init_identity(bbg_identity_t* identity, unsigned int id_depth);
static int bbg_init_public_key(bbg_public_key_t* pk);
static int bbg_init_secret_key(bbg_secret_key_t* sk, unsigned int delegetable_levels,
                               unsigned int id_depth);
static int bbg_init_ciphertext(bbg_ciphertext_t* ciphertext);
static int bbg_init_public_params(bbg_public_params_t* params, unsigned int depth);
static int bbg_init_public_params_from_serialized(bbg_public_params_t* params,
                                                  const uint8_t* serialized);
static int bbg_init_master_key(bbg_master_key_t* mk);
static int bbg_init_key(bbg_key_t* key);
static int bbg_init_identity_from(bbg_identity_t* dst, unsigned int depth,
                                  const bbg_identity_t* src);
// ## SERIALIZE AND DESERIALIZE
static void bbg_serialize_identity(uint8_t* dst, const bbg_identity_t* identity);
static void bbg_serialize_public_key(uint8_t* serialized, bbg_public_key_t* public_key);
static void bbg_serialize_secret_key(uint8_t* serialized, bbg_secret_key_t* secret_key);
static void bbg_serialize_ciphertext(uint8_t* serialized, bbg_ciphertext_t* ciphertext);
static void bbg_serialize_public_params(uint8_t* serialized, bbg_public_params_t* public_params);
static void bbg_deserialize_identity(bbg_identity_t* identity, const uint8_t* src);
static void bbg_deserialize_public_key(bbg_public_key_t* public_key, const uint8_t* serialized);
static void bbg_deserialize_secret_key(bbg_secret_key_t* secret_key, const uint8_t* serialized);
static void bbg_deserialize_ciphertext(bbg_ciphertext_t* ciphertext, const uint8_t* serialized);
// ## CLEAR AND FREE
static void bbg_clear_identity(bbg_identity_t* identity);
static void bbg_clear_public_key(bbg_public_key_t* pk);
static void bbg_clear_secret_key(bbg_secret_key_t* sk);
static void bbg_clear_ciphertext(bbg_ciphertext_t* ciphertext);
static void bbg_clear_public_params(bbg_public_params_t* params);
static void bbg_clear_master_key(bbg_master_key_t* mk);
static void bbg_clear_key(bbg_key_t* key);
// ## HASHING
static void bbg_hash_id(bn_t hashed_id, const unsigned id, const unsigned prefix);
static void bbg_hash_eddsa_pk(bn_t hash, eddsa_pk_t* eddsa_pk);
static void hash_update_u32(Keccak_HashInstance* ctx, uint32_t v);
static void hash_update_tbfe_public_key(Keccak_HashInstance* ctx,
                                        tbfe_bbg_public_key_t* public_key);
static void hash_update_bbg_ciphertext(Keccak_HashInstance* ctx, bbg_ciphertext_t* ciphertext);
static void hash_update_bbg_ciphertexts(Keccak_HashInstance* ctx, vector_t* ciphertexts);
// ## BBG HIBE
static int bbg_convert_identity_to_zp_vector(bn_t* identity_zp_vector,
                                             const bbg_identity_t* identity);
static int bbg_setup(bbg_master_key_t* master_key, bbg_public_key_t* public_key,
                     bbg_public_params_t* public_params, const unsigned total_depth);
static int bbg_decapsulate(bbg_key_t* key, bbg_ciphertext_t* ciphertext,
                           bbg_secret_key_t* secret_key, eddsa_pk_t* eddsa_pk,
                           bbg_public_params_t* public_params, const bbg_identity_t* identity);
static int bbg_encapsulate(bbg_ciphertext_t* ciphertext, gt_t message, bbg_public_key_t* public_key,
                           eddsa_pk_t* eddsa_pk, bbg_public_params_t* public_params,
                           const bbg_identity_t* identity);
static int bbg_copy_identity(bbg_identity_t* dest, const bbg_identity_t* src);
static bool bbg_identities_are_equal(const bbg_identity_t* l, const bbg_identity_t* r);
static int bbg_sample_key(bbg_key_t* key);
static int bbg_key_generation_from_master_key(bbg_secret_key_t* secret_key,
                                              bbg_master_key_t* master_key,
                                              const bbg_identity_t* identity,
                                              bbg_public_params_t* public_params);
static int bbg_key_generation_from_parent(bbg_secret_key_t* secret_key,
                                          bbg_secret_key_t* parent_secret_key,
                                          const bbg_identity_t* identity,
                                          bbg_public_params_t* public_params);
static int bbg_convert_key_to_bit_string(uint8_t* bit_string, bbg_key_t* key);
// ## TBFE
// ### Commented function define the public TBFE interface and are already declared in
// './include/tbfe-bbg.h' int tbfe_bbg_init_public_key (tbfe_bbg_public_key_t * public_key,unsigned
// int total_depth); int tbfe_bbg_public_key_deserialize (tbfe_bbg_public_key_t * public_key,const
// uint8_t * src); void tbfe_bbg_clear_public_key (tbfe_bbg_public_key_t * public_key); int
// tbfe_bbg_init_secret_key (tbfe_bbg_secret_key_t * secret_key,unsigned int
// bloom_filter_size,double false_positive_prob); int tbfe_bbg_secret_key_deserialize
// (tbfe_bbg_secret_key_t * secret_key,const uint8_t * src);
static void tbfe_bbg_vector_secret_key_free(vector_t* vector_secret_key);
// void tbfe_bbg_clear_secret_key (tbfe_bbg_secret_key_t * secret_key);
// int tbfe_bbg_init_ciphertext (tbfe_bbg_ciphertext_t * ciphertext);
// int tbfe_bbg_ciphertext_deserialize (tbfe_bbg_ciphertext_t * ciphertext,const uint8_t * src);
// void tbfe_bbg_clear_ciphertext (tbfe_bbg_ciphertext_t * ciphertext);
static unsigned long compute_tree_size(const unsigned h);
static int tbfe_bbg_index_to_identity(bbg_identity_t* identity, const unsigned long index,
                                      const unsigned height);
// void tbfe_bbg_public_key_serialize (uint8_t * serialized,tbfe_bbg_public_key_t * public_key);
// void tbfe_bbg_secret_key_serialize (uint8_t * serialized,tbfe_bbg_secret_key_t * secret_key);
// void tbfe_bbg_ciphertext_serialize (uint8_t * serialized,tbfe_bbg_ciphertext_t * ciphertext);
// unsigned tbfe_bbg_public_key_size (const tbfe_bbg_public_key_t * public_key);
// unsigned tbfe_bbg_secret_key_size (const tbfe_bbg_secret_key_t * secret_key);
// unsigned tbfe_bbg_ciphertext_size (const tbfe_bbg_ciphertext_t * ciphertext);
static int generate_zero_identity_with_last_component(bbg_identity_t* identity, unsigned int depth,
                                                      unsigned int last_component);
static int derive_key_and_add(vector_t* dst, bbg_public_params_t* params, bbg_master_key_t* msk,
                              const bbg_identity_t* identity, unsigned int total_depth);
// int tbfe_bbg_keygen (tbfe_bbg_public_key_t * public_key,tbfe_bbg_secret_key_t * secret_key);
// int tbfe_bbg_encaps (uint8_t * key,tbfe_bbg_ciphertext_t * ciphertext,tbfe_bbg_public_key_t *
// public_key,unsigned int time_interval); int tbfe_bbg_decaps (uint8_t * key,tbfe_bbg_ciphertext_t
// * ciphertext,tbfe_bbg_secret_key_t * secret_key,tbfe_bbg_public_key_t * public_key); int
// tbfe_bbg_puncture_ciphertext (tbfe_bbg_secret_key_t * secret_key,tbfe_bbg_ciphertext_t *
// ciphertext);
static int puncture_derive_key_and_add(vector_t* dst, bbg_public_params_t* params,
                                       bbg_secret_key_t* sk, const bbg_identity_t* identity);
// int tbfe_bbg_puncture_interval (tbfe_bbg_secret_key_t * secret_key,tbfe_bbg_public_key_t *
// public_key,unsigned int time_interval);

// ## COMPARE
#if defined(BFE_STATIC)
static bool bbg_public_keys_are_equal(bbg_public_key_t* l, bbg_public_key_t* r);
static bool bbg_public_params_are_equal(bbg_public_params_t* l, bbg_public_params_t* r);
static bool bbg_secret_keys_are_equal(bbg_secret_key_t* l, bbg_secret_key_t* r);
static bool bbg_ciphertexts_are_equal(bbg_ciphertext_t* l, bbg_ciphertext_t* r);
bool tbfe_bbg_public_keys_are_equal(tbfe_bbg_public_key_t* l, tbfe_bbg_public_key_t* r);
bool tbfe_bbg_secret_keys_are_equal(tbfe_bbg_secret_key_t* l, tbfe_bbg_secret_key_t* r);
bool tbfe_bbg_ciphertexts_are_equal(tbfe_bbg_ciphertext_t* l, tbfe_bbg_ciphertext_t* r);
bool tbfe_bbg_eddsa_sig_are_equal(tbfe_bbg_ciphertext_t* l, tbfe_bbg_ciphertext_t* r);
#endif

// ##################################################
// ############## FUNCTION DEFINITIONS ##############
// ##################################################

/* >> OpenSSL EdDSA Signatures << */
/**
 * The following functions provide the interface to create and verify
 * signatures with EdDSA.
 */
///@{

static void eddsa_clear_sk(eddsa_sk_t* eddsa_sk) {
  if (eddsa_sk) {
    explicit_bzero(eddsa_sk->key, Ed25519_KEY_BYTES);
  }
}

static void eddsa_clear_pk(eddsa_pk_t* eddsa_pk) {
  if (eddsa_pk) {
    memset(eddsa_pk->key, 0, Ed25519_KEY_BYTES);
  }
}

static void eddsa_clear_sig(eddsa_sig_t* eddsa) {
  if (eddsa) {
    memset(eddsa->sig, 0, Ed25519_SIG_BYTES);
  }
}

/**
 * Generates a new EdDSA key pair.
 * The keys are returned in RAW binary format.
 *
 * @param eddsa_sk[out] - the generated secret signature key
 * @param eddsa_pk[out] - the generated public verification key
 *
 * @return - BFE_SUCCESS when no errors occured, BFE_ERROR otherwise
 */
static int eddsa_keygen(eddsa_sk_t* eddsa_sk, eddsa_pk_t* eddsa_pk) {

  if (!eddsa_pk || !eddsa_sk)
    return BFE_ERROR_INVALID_PARAM;

  int result_status = BFE_SUCCESS;

  EVP_PKEY* pkey     = NULL; // Generate new KeyPair
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
  if (!pctx)
    return BFE_ERROR;

  if (EVP_PKEY_keygen_init(pctx) <= 0) {
    result_status = BFE_ERROR;
    goto clean;
  }

  if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
    result_status = BFE_ERROR;
    goto clean;
  }

  size_t key_len = Ed25519_KEY_BYTES;
  // Extract raw public key
  if (EVP_PKEY_get_raw_public_key(pkey, eddsa_pk->key, &key_len) == EVP_FAILURE ||
      key_len != Ed25519_KEY_BYTES) {
    result_status = BFE_ERROR;
    goto clean;
  }

  // Extract raw private key
  if (EVP_PKEY_get_raw_private_key(pkey, eddsa_sk->key, &key_len) == EVP_FAILURE ||
      key_len != Ed25519_KEY_BYTES) {
    result_status = BFE_ERROR;
  }

clean:
  EVP_PKEY_CTX_free(pctx);
  EVP_PKEY_free(pkey);

  return result_status;
}

/**
 * Sign the given ciphertext vector together with the corresponding tbfe public key.
 * The public key is serialized and hashed together with the ciphertext.
 *
 * @param[out] eddsa      - the generated signature
 * @param[in] ciphertexts - the given ciphertexts that shall be signed
 * @param[in] eddsa_sk    - the secret verification key
 * @param[in] pk          - the corresponding tbfe public key used to generate the ciphertexts
 *
 * @return - BFE_SUCCESS if no error occured, BFE_ERROR otherwise
 */
static int eddsa_sign(eddsa_sig_t* eddsa, vector_t* ciphertexts, eddsa_sk_t* eddsa_sk,
                      tbfe_bbg_public_key_t* pk) {

  if (!eddsa || !ciphertexts || !eddsa_sk || !pk) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int result_status = BFE_SUCCESS;

  // Hash (ciphertexts || pk)
  Keccak_HashInstance ctx;
  Keccak_HashInitialize_SHAKE256(&ctx);
  Keccak_HashUpdate(&ctx, &SIGNATURE_PREFIX, sizeof(SIGNATURE_PREFIX) * 8);
  hash_update_bbg_ciphertexts(&ctx, ciphertexts);
  hash_update_tbfe_public_key(&ctx, pk); // Add public key to hash
  Keccak_HashFinal(&ctx, NULL);
  uint8_t hash_buf[MAX_ORDER_SIZE];
  Keccak_HashSqueeze(&ctx, hash_buf, order_size * 8);

  EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    return BFE_ERROR;
  }

  // Create a EVP_PKEY data element from the raw private key information
  EVP_PKEY* pkey =
      EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, eddsa_sk->key, Ed25519_KEY_BYTES);
  if (!pkey) {
    result_status = BFE_ERROR;
    goto clean;
  }

  // Setup the signature
  if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) == EVP_FAILURE) {
    result_status = BFE_ERROR;
    goto clean;
  }

  // Sign hash
  size_t sig_len = Ed25519_SIG_BYTES;
  int evp_status = EVP_DigestSign(md_ctx, eddsa->sig, &sig_len, hash_buf, order_size);

  if (evp_status == EVP_FAILURE || sig_len != Ed25519_SIG_BYTES) {
    result_status = BFE_ERROR;
  }

clean:
  EVP_PKEY_free(pkey);
  EVP_MD_CTX_free(md_ctx);

  return result_status;
}

/**
 * Verifies the given EdDSA signature.
 *
 * @param[in] ciphertexts - the ciphertext vector which was signed
 * @param[in] eddsa       - the corresponding signature
 * @param[in] eddsa_pk    - the public verification key
 * @param[in] pk          - the tbfe public key used to generate the ciphertexts
 *
 * @return - BFE_SUCCESS if the signature could be verified, BFE_ERROR otherwise
 */
static int eddsa_verify(vector_t* ciphertexts, eddsa_sig_t* eddsa, eddsa_pk_t* eddsa_pk,
                        tbfe_bbg_public_key_t* pk) {

  if (!ciphertexts || !eddsa || !eddsa_pk || !pk) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int result_status = BFE_SUCCESS;

  // Hash (ciphertexts || pk)
  Keccak_HashInstance ctx;
  Keccak_HashInitialize_SHAKE256(&ctx);
  Keccak_HashUpdate(&ctx, &SIGNATURE_PREFIX, sizeof(SIGNATURE_PREFIX) * 8);
  hash_update_bbg_ciphertexts(&ctx, ciphertexts);
  hash_update_tbfe_public_key(&ctx, pk); // Add public key to hash
  Keccak_HashFinal(&ctx, NULL);
  uint8_t hash_buf[MAX_ORDER_SIZE];
  Keccak_HashSqueeze(&ctx, hash_buf, order_size * 8);

  EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    return BFE_ERROR;
  }

  // Create a EVP_PKEY data element from the raw public key information
  EVP_PKEY* pkey =
      EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, eddsa_pk->key, Ed25519_KEY_BYTES);
  if (!pkey) {
    result_status = BFE_ERROR;
    goto clean;
  }

  // Setup verification
  if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) == EVP_FAILURE) {
    result_status = BFE_ERROR;
    goto clean;
  }

  if (EVP_DigestVerify(md_ctx, eddsa->sig, Ed25519_SIG_BYTES, hash_buf, order_size) ==
      EVP_FAILURE) {
    result_status = BFE_ERROR;
  }

clean:
  EVP_PKEY_free(pkey);
  EVP_MD_CTX_free(md_ctx);

  return result_status;
}

///@}

/* >> SIZE << */
/**
 * Return the size in bytes of the given element.
 * This function are defined for 'bbg_identity_t', 'bbg_secret_key_t' and 'bbg_public_params_t'.
 */
///@{

static unsigned int bbg_get_identity_size(const bbg_identity_t* identity) {
  return (identity->depth + 1) * sizeof(uint32_t);
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
///@}

/* >> INIT << */
/**
 * The following functions initialize (already allocted - either heap or stack) structures with
 * initial values. Some structures use RELIC specific datatypes (e.g. bn_t, gt_t, ...), which are
 * also created and defined in this functions.
 */
///@{

/**
 * Initializes the given identity with the provided depth
 *
 * @param[out] identity - already allocated identity element which shall be initialized
 * @param[in] id_depth  - depth of the newly initialized identity
 *
 * @return BFE_SUCCESS if no error occurs, an error code otherwise.
 */
static int bbg_init_identity(bbg_identity_t* identity, unsigned int id_depth) {
  if (!identity) { // Only consider valid pointer
    return BFE_ERROR_INVALID_PARAM;
  }

  identity->id = calloc(id_depth, sizeof(*identity->id));
  if (!identity->id) {
    return BFE_ERROR;
  }
  identity->depth = id_depth;
  return BFE_SUCCESS;
}

static int bbg_init_public_key(bbg_public_key_t* pk) {
  if (!pk) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int ret = BFE_SUCCESS;

  gt_null(pk->pk);
  RLC_TRY {
    gt_new(pk->pk);
  }
  RLC_CATCH_ANY {
    ret = BFE_ERROR;
  }
  return ret;
}

/**
 * Initializes the given BBG secret key.
 *
 * @param[out] sk                 - initialized secret key
 * @param[in] delegetable_levels  - number of delegetable levels of the corresponding identity
 * (defines key size)
 * @param[in] id_depth            - depth of the corresponding identity
 *
 * @return BFE_SUCCESS if no error occurs, an error code otherwise.
 */
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

  RLC_TRY {
    g1_new(sk->a0);
    g2_new(sk->a1);
    g1_new(sk->associated_id);

    for (size_t idx = 0; idx < delegetable_levels; ++idx) {
      g1_new(sk->b[idx]);
    }
  }
  RLC_CATCH_ANY {
    ret = BFE_ERROR;
  }

  return ret;
}

static int bbg_init_ciphertext(bbg_ciphertext_t* ciphertext) {
  if (!ciphertext) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int ret = BFE_SUCCESS;

  gt_null(ciphertext->a);
  g2_null(ciphertext->b);
  g1_null(ciphertext->c);

  RLC_TRY {
    gt_new(ciphertext->a);
    g2_new(ciphertext->b);
    g1_new(ciphertext->c);
  }
  RLC_CATCH_ANY {
    ret = BFE_ERROR;
  }

  return ret;
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
  RLC_TRY {
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
  RLC_CATCH_ANY {
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
  RLC_TRY {
    read_g1(params->g, &serialized);
    read_g2(params->g_hat, &serialized);
    read_g1(params->g2, &serialized);
    read_g1(params->g3, &serialized);

    for (size_t i = 0; i < params->max_delegatable_depth + 1; ++i) {
      read_g1(params->h[i], &serialized);
      g1_mul_pre(params->h_precomputation_tables + i * RLC_EP_TABLE, params->h[i]);
    }
  }
  RLC_CATCH_ANY {
    ret = BFE_ERROR;
  }

  return ret;
}

static int bbg_init_master_key(bbg_master_key_t* mk) {
  if (!mk) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int ret = BFE_SUCCESS;

  g1_null(mk->mk);
  RLC_TRY {
    g1_new(mk->mk);
  }
  RLC_CATCH_ANY {
    ret = BFE_ERROR;
  }
  return ret;
}

static int bbg_init_key(bbg_key_t* key) {
  if (!key) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int ret = BFE_SUCCESS;

  gt_null(key->k);
  RLC_TRY {
    gt_new(key->k);
  }
  RLC_CATCH_ANY {
    ret = BFE_ERROR;
  }

  return ret;
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
///@}

/* >> SERIALIZE AND DESERIALIZE << */
/**
 * The following functions provides primitives to write (serialize) or
 * read (deserialize) structures to/from memory in a predefined order.
 */
///@{

static void bbg_serialize_identity(uint8_t* dst, const bbg_identity_t* identity) {
  write_u32(&dst, identity->depth);
  for (size_t i = 0; i < identity->depth; ++i) {
    write_u32(&dst, identity->id[i]);
  }
}

static void bbg_serialize_public_key(uint8_t* serialized, bbg_public_key_t* public_key) {
  write_gt(&serialized, public_key->pk);
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

static void bbg_serialize_ciphertext(uint8_t* serialized, bbg_ciphertext_t* ciphertext) {
  write_gt(&serialized, ciphertext->a);
  write_g2(&serialized, ciphertext->b);
  write_g1(&serialized, ciphertext->c);
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

static void bbg_deserialize_public_key(bbg_public_key_t* public_key, const uint8_t* serialized) {
  read_gt(public_key->pk, &serialized);
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

static void bbg_deserialize_ciphertext(bbg_ciphertext_t* ciphertext, const uint8_t* serialized) {
  read_gt(ciphertext->a, &serialized);
  read_g2(ciphertext->b, &serialized);
  read_g1(ciphertext->c, &serialized);
}
///@}

/* >> CLEAR AND FREE << */
/**
 * The following functions safely clear unsued strcutures.
 * Senstive data is overwritten and subsequently the memory is freed.
 */
///@{

static void bbg_clear_identity(bbg_identity_t* identity) {
  if (identity) {
    free(identity->id);
    identity->id    = NULL;
    identity->depth = 0;
  }
}

static void bbg_clear_public_key(bbg_public_key_t* pk) {
  if (pk) {
    gt_free(pk->pk);
  }
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

static void bbg_clear_ciphertext(bbg_ciphertext_t* ciphertext) {
  if (ciphertext) {
    g1_free(ciphertext->c);
    g2_free(ciphertext->b);
    gt_free(ciphertext->a);
  }
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

static void bbg_clear_master_key(bbg_master_key_t* mk) {
  if (mk) {
    g1_set_infty(mk->mk);
    g1_free(mk->mk);
  }
}

static void bbg_clear_key(bbg_key_t* key) {
  if (key) {
    gt_zero(key->k);
    gt_free(key->k);
  }
}
///@}

/* >> HASHING << */
/**
 * The following functions provide an interface to hash different kinds of data and
 * combine multpile data items into a single hash.
 * To create domain separation different prefixes shall be used for different data.
 */
///@{

/**
 * This function generates the hash of some unsigned integer.
 */
static void bbg_hash_id(bn_t hashed_id, const unsigned id, const unsigned prefix) {
  // Change the endiness of the input parameter
  const uint32_t prefix_u32 = htole32(prefix);
  const uint32_t id_u32     = htole32(id);

  Keccak_HashInstance ctx;
  Keccak_HashInitialize_SHAKE128(&ctx);
  Keccak_HashUpdate(&ctx, (const uint8_t*)&prefix_u32, sizeof(prefix_u32) * 8);
  Keccak_HashUpdate(&ctx, (const uint8_t*)&id_u32, sizeof(id_u32) * 8);
  Keccak_HashFinal(&ctx, NULL);
  hash_squeeze_zp(hashed_id, &ctx);
}

/**
 * Generates the SHA3 hash of the public key of the given EdDSA key pair
 *
 * @param[out] hash     - generated hash
 * @param[in] eddsa_pk  - EdDSA public key
 * @param[in] prefix    - prefix used for hashing
 */
static void bbg_hash_eddsa_pk(bn_t hash, eddsa_pk_t* eddsa_pk) {
  Keccak_HashInstance ctx;
  Keccak_HashInitialize_SHAKE256(&ctx);
  Keccak_HashUpdate(&ctx, &VERIFICATION_PREFIX, sizeof(VERIFICATION_PREFIX) * 8);
  Keccak_HashUpdate(&ctx, eddsa_pk->key, Ed25519_KEY_BYTES * 8);
  Keccak_HashFinal(&ctx, NULL);
  hash_squeeze_zp(hash, &ctx);
}

/**
 * Updates the hash instance with the given integer..
 *
 * @param[out] ctx  - hash instance
 * @param[in] v     - the input integer
 */
static void hash_update_u32(Keccak_HashInstance* ctx, uint32_t v) {
  v = htole32(v);
  Keccak_HashUpdate(ctx, (const uint8_t*)&v, sizeof(v) * 8);
}

/**
 * Updates the hash instance with the given tbfe public key.
 * The order of the hash updates follows the serialization order
 *
 * @param[out] ctx        - hash instance
 * @param[in] public_key  - the tbfe public key that shall be hashed
 */
static void hash_update_tbfe_public_key(Keccak_HashInstance* ctx,
                                        tbfe_bbg_public_key_t* public_key) {
  // Bloom filter parameter
  hash_update_u32(ctx, public_key->bloom_filter_hashes);
  hash_update_u32(ctx, public_key->bloom_filter_size);
  // Public key
  hash_update_gt(ctx, public_key->pk.pk);
  // Public parameter
  hash_update_u32(ctx, public_key->params.max_delegatable_depth);
  hash_update_g1(ctx, public_key->params.g);
  hash_update_g2(ctx, public_key->params.g_hat);
  hash_update_g1(ctx, public_key->params.g2);
  hash_update_g1(ctx, public_key->params.g3);
  for (size_t i = 0; i < public_key->params.max_delegatable_depth + 1; i++) {
    hash_update_g1(ctx, public_key->params.h[i]);
  }
}

/**
 * Generates the hash of the given BBG ciphertext c = [a,b,c]
 *
 * @param[out] ctx        - hash instance
 * @param[in] ciphertext  - input bbg ciphertext to be hashed
 */
static void hash_update_bbg_ciphertext(Keccak_HashInstance* ctx, bbg_ciphertext_t* ciphertext) {
  hash_update_gt(ctx, ciphertext->a);
  hash_update_g2(ctx, ciphertext->b);
  hash_update_g1(ctx, ciphertext->c);
}

/**
 * Generates the hash of an vector of BBG ciphertexts
 *
 * @param[out] ctx        - hash instance
 * @param[in] ciphertexts - input vector conatining multiple bbg ciphertexts
 */
static void hash_update_bbg_ciphertexts(Keccak_HashInstance* ctx, vector_t* ciphertexts) {
  const unsigned int count = vector_size(ciphertexts);
  for (size_t i = 0; i < count; ++i) {
    // Apply hash function on every ciphertext and add it to old hash
    hash_update_bbg_ciphertext(ctx, vector_get(ciphertexts, i));
  }
}
///@}

/* >> BBG HIBE << */
/**
 * The following functions provide the interface to the BBG HIBE scheme,
 * as well as some utility functions.
 */
///@{

/**
 * Converts an identity element into a vector of Zp elements,
 * by hashing every element of the idenitity-path (from root to ID).
 *
 * @param[out] identity_zp_vector - output vector of Zp elements
 * @param[in] identity            - identity element to be converted
 *
 * @return BFE_SUCESS if no errors occur, an error code otherwise
 */
static int bbg_convert_identity_to_zp_vector(bn_t* identity_zp_vector,
                                             const bbg_identity_t* identity) {
  int result_status = BFE_SUCCESS;

  for (size_t i = 0; i < identity->depth; ++i) {
    bn_null(identity_zp_vector[i]);
  }

  RLC_TRY {
    for (size_t i = 0; i < identity->depth; ++i) {
      bn_new(identity_zp_vector[i]);
      bbg_hash_id(identity_zp_vector[i], identity->id[i], IDENTITY_PREFIX);
    }
  }
  RLC_CATCH_ANY {
    result_status = BFE_ERROR;
  }

  return result_status;
}

/**
 * Implements the BBG HIBE setup function.
 * Parameters g, g_hat, g_2, g_3, h_1, ..., h_l are randomly generated group elements (where l =
 * total_depth). Alpha is random in Zp and g_1 = g_hat^alpha. The master key is set to g_2^alpha.
 * The public key is set to e(g_2, g_1), where e is a bilinear function.
 *
 * @param[out] master_key     - generated master key used for key derivation
 * @param[out] public_key     - generated public key
 * @param[out] public_params  - generated public parameter set
 * @param[in] total_depth     - the total depth of the interval tree (includes two layers for bloom
 * filter keys and CHK signature)
 *
 * @return BFE_SUCESS if no errors occur, an error code otherwise
 */
static int bbg_setup(bbg_master_key_t* master_key, bbg_public_key_t* public_key,
                     bbg_public_params_t* public_params, const unsigned total_depth) {
  int result_status = BFE_SUCCESS;

  // Create new group elements and initialize those
  g2_t original_public_key_pk;
  g2_null(original_public_key_pk);

  bn_t alpha;
  bn_null(alpha);

  RLC_TRY {
    g2_new(original_public_key_pk);
    bn_new(alpha);

    // Randomize public parameters
    g1_rand(public_params->g);
    g2_rand(public_params->g_hat);
    g1_rand(public_params->g2);
    g1_rand(public_params->g3);

    // Initialize the precomputation table of h_1, ..., h_l with the values of h_1, ..., h_l.
    // Note that the precomp-table is used for faster exponatiation
    for (size_t i = 0; i < total_depth; ++i) {
      g1_rand(public_params->h[i]);
      g1_mul_pre(public_params->h_precomputation_tables + i * RLC_EP_TABLE, public_params->h[i]);
    }

    // Choose a random alpha from Z_p^*
    zp_rand(alpha);

    // We precompute pk = e(g_2, \pk), and save it as our actual public key
    g2_mul(original_public_key_pk, public_params->g_hat, alpha);
    pc_map(public_key->pk, public_params->g2, original_public_key_pk);
    // Master key mk = g_2^alpha
    g1_mul(master_key->mk, public_params->g2, alpha);

    public_params->max_delegatable_depth = total_depth - 1;
  }
  // Clean up if errors occured
  RLC_CATCH_ANY {
    result_status = BFE_ERROR;
  }
  RLC_FINALLY {
    bn_free(alpha);
    g2_free(original_public_key_pk);
  }

  return result_status;
}

/**
 * Encapsulates a newly generated Key with the BBG HIBE scheme.
 *
 * @param[out] ciphertext     - the generated ciphertext
 * @param[out] message        - the freshly generated plaintext message (in this case a symetric
 * key)
 * @param[in] public_key      - the public key used for encapsulation
 * @param[in] eddsa_pk        - the public EdDSA key
 * @param[in] public_params   - public parameter set of the BBG HIBE
 * @param[in] identity        - the identity for which the message shall be encrypted
 *
 * @return BFE_SUCCESS if no error occurs, an error code otherwise
 */
static int bbg_encapsulate(bbg_ciphertext_t* ciphertext, gt_t message, bbg_public_key_t* public_key,
                           eddsa_pk_t* eddsa_pk, bbg_public_params_t* public_params,
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
  RLC_TRY {
    bn_new(u);
    g1_new(tmp);

    // u = H(VERIFICATION_PREFIX | eddsa_pk) --> generate hash of eddsa public key for CHK signature
    bbg_hash_eddsa_pk(u, eddsa_pk);

    // Compute the encryption.
    // ## c = (g_3 * h_1^I_1 * ... * h_k^I_k)^u
    g1_copy(ciphertext->c, public_params->g3);
    for (size_t i = 0; i < identity->depth; ++i) {
      g1_mul_fix(tmp, &public_params->h_precomputation_tables[i * RLC_EP_TABLE],
                 identity_zp_vector[i]);
      // c = c*tmp
      g1_add(ciphertext->c, ciphertext->c, tmp);
    }

    // tmp = h_{k+1}^u --> encrypt with eddsa_ok as identity (e.g. add an additional CHK level)
    g1_mul_fix(tmp, &public_params->h_precomputation_tables[identity->depth * RLC_EP_TABLE], u);
    g1_add(ciphertext->c, ciphertext->c, tmp);

    // Choose a random s from Z_p^*.
    zp_rand(u);

    // ## a =  e(g2,g^alpha)^u * M
    // public_key->pk stores already precomputed e(g2,g^alpha)
    gt_exp(ciphertext->a, public_key->pk, u);
    gt_mul(ciphertext->a, ciphertext->a, message);
    // ## b = g^u
    g2_mul(ciphertext->b, public_params->g_hat, u);
    // ## c = c^u
    g1_mul(ciphertext->c, ciphertext->c, u);
  }
  RLC_CATCH_ANY {
    result_status = BFE_ERROR;
  }
  RLC_FINALLY {
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

/**
 * Decapsulates a given encapsulated secret from an BBG HIBE ciphertext.
 *
 * @param[out] key            - the received decapsulated key (or the secret)
 * @param[in] ciphertext      - the given BBG ciphertext which shall be decapsulated
 * @param[in] secret_key      - the secret key used to decapsulate the ciphertext
 * @param[in] eddsa_pk        - the EdDSA public key
 * @param[in] public_params   - public parameter set of the BBG HIBE
 * @param[in] identity        - identity for which the message was encapsulated
 *
 * @return BFE_SUCCESS if no error occurs, an error code otherwise
 */
static int bbg_decapsulate(bbg_key_t* key, bbg_ciphertext_t* ciphertext,
                           bbg_secret_key_t* secret_key, eddsa_pk_t* eddsa_pk,
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

  // Create arrays of size 2 to use for 'pc_map_sim' function
  g1_t g1s[2];
  g2_t g2s[2];
  g1_null(g1s[0]);
  g1_null(g1s[1]);
  g2_null(g2s[0]);
  g2_null(g2s[1]);

  RLC_TRY {
    bn_new(u);
    bn_new(w);
    g1_new(g1s[0]);
    g1_new(g1s[1]);
    g2_new(g2s[0]);
    g2_new(g2s[1]);

    // u = H(VERIFICATION_PREFIX | eddsa_pk) --> generate hash of eddsa public key to verify CHK
    // signature
    bbg_hash_eddsa_pk(u, eddsa_pk);

    // Choose a random w from Z_p^*.
    zp_rand(w);

    // g1s[0] = (h_1^I_1 * ... * h_k^I_k * g_3)
    g1_copy(g1s[0], public_params->g3);
    for (size_t i = 0; i < identity->depth; ++i) {
      g1_mul_fix(g1s[1], &public_params->h_precomputation_tables[i * RLC_EP_TABLE],
                 identity_zp_vector[i]);
      g1_add(g1s[0], g1s[0], g1s[1]);
    }
    // g1_copy(g1s[0], secret_key->associated_id); // --> also possible instead of for-loop

    // ## generate new sk for identity eddsa_pk (CHK)
    // g1s[0] = g1s[0] * h_{k+1}^u
    g1_mul_fix(g1s[1], &public_params->h_precomputation_tables[identity->depth * RLC_EP_TABLE], u);
    g1_add(g1s[0], g1s[0], g1s[1]);

    // g1s[1] = (g1s[0]^w * b_k^u * a0')^-1 ==> a0 of new sk
    g1_mul_sim(g1s[1], g1s[0], w, secret_key->b[0], u);
    g1_add(g1s[1], secret_key->a0, g1s[1]);
    g1_neg(g1s[1], g1s[1]); // ^-1 --> divide
    // g2s[1] = B
    g2_copy(g2s[1], ciphertext->b);
    // g1s[0] = C
    g1_copy(g1s[0], ciphertext->c);
    // g2s[0] = g^w * a1' ==> a1 of new sk
    g2_mul(g2s[0], public_params->g_hat, w);
    g2_add(g2s[0], g2s[0], secret_key->a1);

    // key = e(g1s[0], g2s[0]) * e(g1s[1]. g2s[1])
    pc_map_sim(key->k, g1s, g2s, 2);
    // key = key * A
    gt_mul(key->k, key->k, ciphertext->a);
  }
  RLC_CATCH_ANY {
    result_status = BFE_ERROR;
  }
  RLC_FINALLY {
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

/**
 * Copy an identity element to another one.
 * Depth of both identities has to be euqal.
 *
 * @param [out] dest  - allocated identity struct pointer, to which shall be copied
 * @param [in] src    - identity which shall be copied
 */
static int bbg_copy_identity(bbg_identity_t* dest, const bbg_identity_t* src) {
  if (!dest || !src || dest->depth != src->depth) {
    return BFE_ERROR_INVALID_PARAM;
  }

  memcpy(dest->id, src->id, sizeof(src->id[0]) * src->depth);
  return BFE_SUCCESS;
}

/**
 * Checks if two identities are equal.
 * E.g. they have the same depth and the path to root is equal.
 *
 * @param[in] l - left identity
 * @param[in] r - rigth identity
 *
 * @return True if both identities are equal and False otherwise
 */
static bool bbg_identities_are_equal(const bbg_identity_t* l, const bbg_identity_t* r) {
  return l->depth == r->depth && memcmp(l->id, r->id, sizeof(l->id[0]) * l->depth) == 0;
}

static int bbg_sample_key(bbg_key_t* key) {
  if (!key) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int ret = BFE_SUCCESS;
  RLC_TRY {
    gt_rand(key->k);
  }
  RLC_CATCH_ANY {
    ret = BFE_ERROR;
  }
  return ret;
}

/**
 * Derive some secret key for a specific identity directly from the master key.
 * The function follows the steps of the BBG HIBE key generation (where k is the depth of the
 * identity and l is total depth of the tree):
 *  - [in] public_params = [g, g_1, g_2, g_3, h_1, ..., h_l]
 *  - [in] master_key mk = g2^alpha
 *  - [out] secret_key = [mk*(h_1^I_1 * ... * h_k^I_k * g_3)^r, g^r, h_{k+1}^r, ..., h_l^r] = [a_0,
 * a_1, b_{k+1}, ..., b_l]
 *
 * @param[out] secret_key   - generated secret key, which is derived from the master key
 * @param[in] master_key    - master key from BBG setup
 * @param[in] identity      - the identity for which a secret key shall be generated
 * @param[in] public_params - public parameter set of the BBG setup
 *
 * @return BFE_SUCESS if no errors occur, an error code otherwise
 */
static int bbg_key_generation_from_master_key(bbg_secret_key_t* secret_key,
                                              bbg_master_key_t* master_key,
                                              const bbg_identity_t* identity,
                                              bbg_public_params_t* public_params) {
  // const unsigned total_depth            = public_params->max_delegatable_depth + 1;
  // const unsigned num_total_levels       = total_depth - identity->depth;
  // const unsigned num_delegatable_levels = num_total_levels - 1;

  int result_status = BFE_SUCCESS;

  g1_t h_i_to_the_identity_i;
  bn_t* identity_zp_vector = calloc(sizeof(*identity_zp_vector), identity->depth);
  bn_t v;

  g1_null(h_i_to_the_identity_i);
  bn_null(v);

  RLC_TRY {
    g1_new(secret_key->associated_id);

    g1_new(h_i_to_the_identity_i);
    bn_new(v);

    // Identity has to be converted into an zp vector (e.g. like a hash function).
    // identity_zp_vector = {i=1 to k} h_i^{H(0||I_i) -> hashed identity, where I_i =
    // identity->id[i]
    bbg_convert_identity_to_zp_vector(identity_zp_vector, identity);

    // Choose a random v from Z_p^*.
    zp_rand(v);

    // ### Calculate sk = [a_0, a_1, b_{k+1}, ..., b_l]
    // ## a_0 = mk * (prod_{i=1 to k} h_i^{H(0||I_i)} * g_3)^v.
    // 1.) associated_id = (prod_{i=1 to k} h_i^{H(0||I_i)} * g_3) --> keep this product for further
    // key delegations
    g1_copy(secret_key->associated_id, public_params->g3);
    for (size_t i = 0; i < identity->depth; ++i) {
      g1_mul_fix(h_i_to_the_identity_i, &public_params->h_precomputation_tables[i * RLC_EP_TABLE],
                 identity_zp_vector[i]);
      g1_add(secret_key->associated_id, secret_key->associated_id, h_i_to_the_identity_i);
    }
    // 2.) a0 = (associated_id)^v
    g1_mul(secret_key->a0, secret_key->associated_id, v);
    // 3.) a0 = a0 * mk
    g1_add(secret_key->a0, master_key->mk, secret_key->a0);

    // ## a_1 = g^v
    g2_mul(secret_key->a1, public_params->g_hat, v);

    // ## b_{k+1} ... b_l= h_{k+1}^v ... h_l^v -> in this case b[0] ... b[l-k]
    for (size_t i = 0; i < secret_key->num_delegatable_levels; ++i) {
      // Consider offset on precomp_table!
      g1_mul_fix(secret_key->b[i],
                 &public_params->h_precomputation_tables[(identity->depth + i) * RLC_EP_TABLE], v);
    }

    // Upate identity of secret key (e.g. identity associated with the key)
    result_status = bbg_copy_identity(&secret_key->identity, identity);
  }
  // Clean up if errors occured
  RLC_CATCH_ANY {
    result_status = BFE_ERROR;
  }
  RLC_FINALLY {
    g1_free(h_i_to_the_identity_i);

    for (size_t i = 0; i < identity->depth; ++i) {
      bn_free(identity_zp_vector[i]);
    }
    free(identity_zp_vector);

    bn_free(v);
  }

  return result_status;
}

/**
 * Derive the secret key for a specific identity directly from its parent node.
 * The function follows the steps of the BBG HIBE key generation (where k is the depth of the
 * identity, k-1 is depth of the parent node and l is total depth of the tree):
 *  - [in] public_params = [g, g_1, g_2, g_3, h_1, ..., h_l]
 *  - [in] parent_secret_key = [a_0', a_1', b_k', ..., b_l']
 *  - [out] secret_key = [a_0' * b_k'^I_k * (h_1^I_1 * ... * h_k^I_k * g_3)^r, a_1' * g^r, b_{k+1}'
 * * h_{k+1}^r, ..., b_l' * h_l^r] = [a_0, a_1, b_{k+1}, ..., b_l]
 *
 * @param[out] secret_key       - generated secret key, delegated from the parent node's secret key
 * @param[in] parent_secret_key - secret key of parent node
 * @param[in] identity          - the identity for which a secret key shall be generated
 * @param[in] public_params     - public parameter set of the BBG setup
 *
 * @return BFE_SUCESS if no errors occur, an error code otherwise
 */
static int bbg_key_generation_from_parent(bbg_secret_key_t* secret_key,
                                          bbg_secret_key_t* parent_secret_key,
                                          const bbg_identity_t* identity,
                                          bbg_public_params_t* public_params) {

  // Sanity check, if parent_secret_key is actually derived from a parent node of the given identity
  const unsigned total_depth  = public_params->max_delegatable_depth + 1;
  const unsigned parent_depth = total_depth - parent_secret_key->num_delegatable_levels;
  if (parent_depth != (identity->depth - 1)) {
    return BFE_ERROR_INVALID_PARAM;
  }

  // const unsigned num_total_levels       = total_depth - identity->depth;
  // const unsigned num_delegatable_levels = num_total_levels - 1;

  int result_status = BFE_SUCCESS;

  bn_t w;
  bn_t u;

  bn_null(w);
  bn_null(u);

  RLC_TRY {
    bn_new(w);
    bn_new(u);

    // Consider: parent_depth = k-1  and child_depth = k

    // Hash ID_k of the current identity -> w = H(PREFIX | I_k) = H_k
    bbg_hash_id(w, identity->id[identity->depth - 1], IDENTITY_PREFIX);

    // secret_key->associated_id = h_k^w = h_k^H_k
    g1_mul_fix(secret_key->associated_id,
               &public_params->h_precomputation_tables[(identity->depth - 1) * RLC_EP_TABLE], w);

    // UPDATE: secret_key->associated_id
    // --> parent_secret_key->associated_id = g_3 * h_1^H_1 * ... * h_{k-1}^H_{k-1}
    g1_add(secret_key->associated_id, parent_secret_key->associated_id, secret_key->associated_id);

    // Choose a random w from Z_p^*.
    zp_rand(u);

    // ## a_0 = b_k'^H_k * (g_3 * h_1^H_1 * ... * h_k^H_k)^u *  a_0'
    // where a_0' is parent_key->a0
    // IMPORTANT: b_k' = b[0] of parent key
    g1_mul_sim(secret_key->a0, parent_secret_key->b[0], w, secret_key->associated_id, u);
    g1_add(secret_key->a0, secret_key->a0, parent_secret_key->a0);

    // ## a_1 = a_1' * g^u
    // where a_1' is parent_secret_key->a1
    g2_mul(secret_key->a1, public_params->g_hat, u);
    g2_add(secret_key->a1, parent_secret_key->a1, secret_key->a1);

    // ## b_{k+1} ... b_l= h_{k+1}^v ... h_l^v -> in this case b[0] ... b[l-k]
    for (size_t i = 0; i < secret_key->num_delegatable_levels; ++i) {
      g1_mul_fix(secret_key->b[i],
                 &public_params->h_precomputation_tables[(identity->depth + i) * RLC_EP_TABLE], u);
      g1_add(secret_key->b[i], secret_key->b[i], parent_secret_key->b[i + 1]);
    }

    // Update identity of secret key (e.g. identity associated with the key)
    result_status = bbg_copy_identity(&secret_key->identity, identity);
  }
  // Clean up if errors occured
  RLC_CATCH_ANY {
    result_status = BFE_ERROR;
  }
  RLC_FINALLY {
    bn_free(u);
    bn_free(w);
  }

  return result_status;
}

static int bbg_convert_key_to_bit_string(uint8_t* bit_string, bbg_key_t* key) {
  int result_status = BFE_SUCCESS;
  RLC_TRY {
    // Hash binary represented bit string.
    uint8_t serialized_key[GT_SIZE_COMPRESSED];
    gt_write_bin(serialized_key, GT_SIZE_COMPRESSED, key->k, 1);
    md_kdf(bit_string, SECURITY_PARAMETER, serialized_key, GT_SIZE_COMPRESSED);
  }
  RLC_CATCH_ANY {
    result_status = BFE_ERROR;
  }
  RLC_FINALLY {}

  return result_status;
}
///@}

/* >> TBFE << */
/**
 * The following functions provide the interface to the TBFE scheme,
 * as well as some utility functions.
 * More detailed documentation can be found in the './include/tbfe-bbg.h' header file.
 */
///@{

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

int tbfe_bbg_public_key_deserialize(tbfe_bbg_public_key_t* public_key, const uint8_t* src) {
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

int tbfe_bbg_secret_key_deserialize(tbfe_bbg_secret_key_t* secret_key, const uint8_t* src) {
  if (!secret_key || !src) {
    return BFE_ERROR_INVALID_PARAM;
  }

  int err = BFE_SUCCESS;

  omp_init_lock(&secret_key->bloom_filter_mutex);

  const unsigned int sk_bloom_count = read_u32(&src);
  const unsigned int sk_time_count  = read_u32(&src);
  secret_key->next_interval         = read_u32(&src);
  secret_key->bloom_filter          = bf_read(&src);

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

static void tbfe_bbg_vector_secret_key_free(vector_t* vector_secret_key) {
  for (size_t i = 0; i < vector_size(vector_secret_key); ++i) {
    bbg_secret_key_t* sk = vector_get(vector_secret_key, i);
    bbg_clear_secret_key(sk);
    free(sk);
  }
  vector_free(vector_secret_key);
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

  return ret;
}

int tbfe_bbg_ciphertext_deserialize(tbfe_bbg_ciphertext_t* ciphertext, const uint8_t* src) {
  if (!ciphertext || !src) {
    return BFE_ERROR_INVALID_PARAM;
  }

  unsigned int ciphertext_count = read_u32(&src);

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

  memcpy(ciphertext->eddsa.sig, src, Ed25519_SIG_BYTES);
  src += Ed25519_SIG_BYTES;

  memcpy(ciphertext->eddsa_pk.key, src, Ed25519_KEY_BYTES);
  src += Ed25519_KEY_BYTES;

  return BFE_SUCCESS;
}

void tbfe_bbg_clear_ciphertext(tbfe_bbg_ciphertext_t* ciphertext) {
  if (ciphertext) {
    for (size_t idx = 0; idx < vector_size(ciphertext->Cs); ++idx) {
      bbg_ciphertext_t* ct = vector_get(ciphertext->Cs, idx);
      bbg_clear_ciphertext(ct);
      free(ct);
    }
    eddsa_clear_pk(&ciphertext->eddsa_pk);
    eddsa_clear_sig(&ciphertext->eddsa);
    vector_free(ciphertext->Cs);
  }
}

/**
 * Calculates the  size of a binary tree with depth h-1 (root is at level 1).
 * E.g.: tree with heigh h = 2 --> 2^3-1 = 7 nodes
 *      o
 *     / \
 *    o   o
 *   / \ / \
 *  o   oo  o
 */
static inline unsigned long compute_tree_size(const unsigned h) {
  return (2ul << h) - 1;
}

/**
 * This function builds a mapping between index of nodes (time interval) and identities.
 * Currently ALL nodes in the tree are used as time interval.
 * The mapping does a pre-order traversal of the tree and assigns indices in that order.
 *
 * @param[out] identity - generated identity element
 * @param[in] index     - index of one node in the tree (starting at 1)
 * @param[in] height    - height of the tree without bloom filter keys and CHK layer
 *
 * @return BFE_SUCESS if no errors occur, an error code otherwise
 */
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

  // traverse tree in pre-order --> e.g. root -> left -> right
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

void tbfe_bbg_public_key_serialize(uint8_t* serialized, tbfe_bbg_public_key_t* public_key) {
  write_u32(&serialized, public_key->bloom_filter_hashes);
  write_u32(&serialized, public_key->bloom_filter_size);

  bbg_serialize_public_key(serialized, &public_key->pk);
  serialized += BBG_PUBLIC_KEY_SIZE;
  bbg_serialize_public_params(serialized, &public_key->params);
}

void tbfe_bbg_secret_key_serialize(uint8_t* serialized, tbfe_bbg_secret_key_t* secret_key) {
  unsigned sk_bloom_count = vector_size(secret_key->sk_bloom);
  unsigned sk_time_count  = vector_size(secret_key->sk_time);

  write_u32(&serialized, sk_bloom_count);
  write_u32(&serialized, sk_time_count);
  write_u32(&serialized, secret_key->next_interval);
  bf_write(&serialized, &secret_key->bloom_filter);

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

void tbfe_bbg_ciphertext_serialize(uint8_t* serialized, tbfe_bbg_ciphertext_t* ciphertext) {
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

  memcpy(serialized, ciphertext->eddsa.sig, Ed25519_SIG_BYTES);
  serialized += Ed25519_SIG_BYTES;

  memcpy(serialized, ciphertext->eddsa_pk.key, Ed25519_KEY_BYTES);
  serialized += Ed25519_KEY_BYTES;
}

unsigned tbfe_bbg_public_key_size(const tbfe_bbg_public_key_t* public_key) {
  return BBG_PUBLIC_KEY_SIZE + bbg_get_public_params_size(&public_key->params) +
         2 * sizeof(uint32_t);
}

unsigned tbfe_bbg_secret_key_size(const tbfe_bbg_secret_key_t* secret_key) {
  unsigned int sk_bloom_count = vector_size(secret_key->sk_bloom);
  unsigned int sk_time_count  = vector_size(secret_key->sk_time);

  unsigned int total_size = 3 * sizeof(uint32_t) + bf_serialized_size(&secret_key->bloom_filter);
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

unsigned tbfe_bbg_ciphertext_size(const tbfe_bbg_ciphertext_t* ciphertext) {
  const unsigned ciphertext_count = vector_size(ciphertext->Cs);
  return 2 * sizeof(uint32_t) + (ciphertext_count * BBG_CIPHERTEXT_SIZE) + SECURITY_PARAMETER +
         Ed25519_SIG_BYTES + Ed25519_KEY_BYTES;
}

/**
 * Generates an identity element, where all elements of the identity path are set to 0, execpt the
 * last one, which is set to the specfied value.
 *
 * @param[out] identity       - allocated identity element which shall be initialized
 * @param[in] depth           - depth of the identity in the tree
 * @param[in] last_component  - value of the last component in the identity path (e.g. id at last
 * level)
 *
 * @return BFE_SUCESS if no errors occur, an error code otherwise
 */
static int generate_zero_identity_with_last_component(bbg_identity_t* identity, unsigned int depth,
                                                      unsigned int last_component) {
  int ret = bbg_init_identity(identity, depth);
  if (!ret) {
    memset(identity->id, 0, sizeof(identity->id[0]) * (depth - 1));
    identity->id[depth - 1] = last_component;
  }
  return ret;
}

/**
 * Derives a BBG secret key, corresponding to some given identity, from the BBG master key and
 * adds it to the specified vector.
 */
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

/**
 * Implements the TBFE keygen function.
 */
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

  // Do the bloom filer key generation in parallel
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
      // We use identity '0i' at depth 2, since we start at depth 1 with identity '0' as first time
      // interval! The bloom filters just add one layer to identity '0'
      ret |= generate_zero_identity_with_last_component(&identity_0i, 2, identity);
      if (ret) {
        goto clear_loop;
      }

      // Get the bloom filter key and add it the per-thread 'secret key vector'
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

  // Puncture sk_0 and compute keys for its children (00, 01) and for identity 1 (e.g. next time
  // intervals).
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

/**
 * Implements the TBFE encapsulation function.
 */
int tbfe_bbg_encaps(uint8_t* key, tbfe_bbg_ciphertext_t* ciphertext,
                    tbfe_bbg_public_key_t* public_key, unsigned int time_interval) {
  if (!ciphertext || !public_key) {
    return BFE_ERROR_INVALID_PARAM;
  }

  // Get the identity of the current time interval and store it in 'tau' --> e.g. the identity for
  // which the message shall be encrypted
  bbg_identity_t tau = {0, NULL};
  int result_status =
      tbfe_bbg_index_to_identity(&tau, time_interval, public_key->params.max_delegatable_depth - 1);
  if (result_status) {
    goto clear_tau;
  }

  // Generate the all tau plus bloom identity.
  const unsigned tau_i_depth = tau.depth + 1;
  bbg_identity_t identity_tau_i; // Bloom filter key identities are on level below 'tau'
  result_status = bbg_init_identity_from(&identity_tau_i, tau_i_depth, &tau); // Get path to 'tau'
  if (result_status) {
    goto clear_identity_tau_i;
  }

  eddsa_sk_t eddsa_sk;
  result_status = eddsa_keygen(&eddsa_sk, &ciphertext->eddsa_pk);
  if (result_status) {
    goto clear_eddsa_sk;
  }

  // Initialize and sample a random Key to encapsulate
  bbg_key_t _key;
  result_status = bbg_init_key(&_key);
  if (result_status) {
    goto clear;
  }

  result_status = bbg_sample_key(&_key);
  if (result_status) {
    goto clear;
  }

  // If the ciphertext variable is re-used, old items have to be remove from the vector
  if (vector_size(ciphertext->Cs)) {
    for (size_t idx = 0; idx < vector_size(ciphertext->Cs); ++idx) {
      bbg_ciphertext_t* ct = vector_get(ciphertext->Cs, idx);
      bbg_clear_ciphertext(ct);
      free(ct);
    }
    vector_clear(ciphertext->Cs);
  }

  // Generate random c to get the bloom filter indices
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

    // For all k hash functions encapsulate the corresponding identity with the BBG HIBE --> k
    // ciphertexts
    result_status = bbg_encapsulate(ct, _key.k, &public_key->pk, &ciphertext->eddsa_pk,
                                    &public_key->params, &identity_tau_i);
    if (result_status) {
      goto clear_ciphertext;
    }

    // Accumulate all k ciphertexts in Cs
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

  // Sign the ciphertexts
  result_status = eddsa_sign(&ciphertext->eddsa, ciphertext->Cs, &eddsa_sk, public_key);
  if (result_status) {
    goto clear;
  }

  ciphertext->time_interval = time_interval;
  // Convert the key generated by BBG HIBE scheme into a bit string.
  result_status = bbg_convert_key_to_bit_string(key, &_key);

clear:
  bbg_clear_key(&_key);
clear_eddsa_sk:
  eddsa_clear_sk(&eddsa_sk);
clear_identity_tau_i:
  bbg_clear_identity(&identity_tau_i);
clear_tau:
  bbg_clear_identity(&tau);
  return result_status;
}

/**
 * Implements the TBDE decapsulation function.
 */
int tbfe_bbg_decaps(uint8_t* key, tbfe_bbg_ciphertext_t* ciphertext,
                    tbfe_bbg_secret_key_t* secret_key, tbfe_bbg_public_key_t* public_key) {
  if (!key || !ciphertext || !secret_key || !public_key) {
    return BFE_ERROR_INVALID_PARAM;
  }

  // Sanity check to see if the ciphertext and the secret key belong to the same time interval
  if (secret_key->next_interval - 1 != ciphertext->time_interval) {
    return BFE_ERROR;
  }

  // Get the identity of the current time interval and store it in 'tau'
  bbg_identity_t tau = {0, NULL};
  int result_status  = tbfe_bbg_index_to_identity(&tau, secret_key->next_interval - 1,
                                                 public_key->params.max_delegatable_depth - 1);
  if (result_status) {
    result_status = BFE_ERROR;
    goto clear_tau;
  }

  // Generate the tau plus bloom identity at depth 'tau.depth + 1'
  const unsigned int tau_i_depth = tau.depth + 1;
  bbg_identity_t tau_prime       = {0, NULL};
  result_status                  = bbg_init_identity_from(&tau_prime, tau_i_depth, &tau);
  if (result_status) {
    goto clear_tau_prime;
  }

  // Initialize and empty Key to hold the decapsulated message
  bbg_key_t _key;
  result_status = bbg_init_key(&_key);
  if (result_status) {
    goto clear_key;
  }

  omp_set_lock(&secret_key->bloom_filter_mutex);

  // Use this variables to store the index (1...k) of the first bloom filter key,
  // that can decapsulate the ciphertext and is not punctured yet
  int decapsulating_identity_index = -1; // in [1..k] -> points to the right ciphertext
  unsigned decapsulating_identity  = 0;  // in [1..m] -> points to the right secret key

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

  // Retrieve [ciphertext, secret key] - pair
  bbg_secret_key_t* sk_id         = vector_get(secret_key->sk_bloom, decapsulating_identity);
  bbg_ciphertext_t* ciphertext_id = vector_get(ciphertext->Cs, decapsulating_identity_index);

  // Verify EdDSA signatures on the ciphertexts.
  result_status =
      eddsa_verify(ciphertext->Cs, &ciphertext->eddsa, &ciphertext->eddsa_pk, public_key);
  if (result_status) {
    goto clear;
  }

  // Decapsulate the ciphertext to get the key.
  result_status = bbg_decapsulate(&_key, ciphertext_id, sk_id, &ciphertext->eddsa_pk,
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

/**
 * Puncture the secret key with the given ciphertext.
 */
int tbfe_bbg_puncture_ciphertext(tbfe_bbg_secret_key_t* secret_key,
                                 tbfe_bbg_ciphertext_t* ciphertext) {
  if (!secret_key || !ciphertext) {
    return BFE_ERROR_INVALID_PARAM;
  }

  omp_set_lock(&secret_key->bloom_filter_mutex);
  // Add c (randomness) to the bloom filter.
  for (unsigned int i = 0; i < secret_key->bloom_filter.hash_count; ++i) {
    unsigned int pos =
        bf_get_position(i, ciphertext->c, SECURITY_PARAMETER, secret_key->bloom_filter.bitset.size);
    bitset_set(&secret_key->bloom_filter.bitset, pos);

    // If the corresponding bloom filter key still exist, delete it
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

/**
 * Derives a BBG secret key, corresponding to some given identity, from its parent node and
 * adds it to the specified vector.
 * The parent node is represented by the secrety key of the parent identity.
 */
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

/**
 * Punctures the secret key with the next time interval.
 */
int tbfe_bbg_puncture_interval(tbfe_bbg_secret_key_t* secret_key, tbfe_bbg_public_key_t* public_key,
                               unsigned int time_interval) {
  if (!secret_key || !public_key) {
    return BFE_ERROR_INVALID_PARAM;
  }
  // NOTE: time_interval refers to the next epoch,
  // therefore tau contains the identity of the new timer interval
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

  // Reset the bloom filter (e.g. reset ciphertext puncturing).
  bf_reset(&secret_key->bloom_filter);

  // Clear the existing bloom filter keys
  const unsigned bloom_filter_size = public_key->bloom_filter_size;
  tbfe_bbg_vector_secret_key_free(secret_key->sk_bloom);
  secret_key->sk_bloom = vector_new(bloom_filter_size);
  if (!secret_key->sk_bloom) {
    result_status = BFE_ERROR;
    goto clear_tau;
  }

  // Generate new bloom filter keys for the time interval tau.
  // Do this in parallel.
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
      // NOTE: now the keys are derived from the parent key, not from master key
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

  // If we are not in the leaf of the tree, we have to generate keys for its children
  // --> create keys for the next time intervals (think of the tree structure)
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

    // Generate key for the right child.
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
///@}

/* >> COMPARE << */

#if defined(BFE_STATIC)

/* Function definitions */
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

bool tbfe_bbg_eddsa_sig_are_equal(tbfe_bbg_ciphertext_t* l, tbfe_bbg_ciphertext_t* r) {
  return memcmp(l->eddsa.sig, r->eddsa.sig, Ed25519_SIG_BYTES) == 0;
}
#endif
