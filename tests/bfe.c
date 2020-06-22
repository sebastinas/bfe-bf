#include "../include/bfe-bf.h"
#undef DOUBLE
#undef CALL

#include <cgreen/cgreen.h>

Describe(BFE_BF);
BeforeEach(BFE_BF) {}
AfterEach(BFE_BF) {}

#define KEY_SIZE 32

Ensure(BFE_BF, encrypt_decrypt) {
  bfe_bf_secret_key_t sk;
  bfe_bf_public_key_t pk;

  assert_true(!bfe_bf_init_secret_key(&sk));
  assert_true(!bfe_bf_init_public_key(&pk));
  assert_true(!bfe_bf_keygen(&pk, &sk, KEY_SIZE, 50, 0.001));

  bfe_bf_ciphertext_t ciphertext;

  uint8_t K[KEY_SIZE], decrypted[KEY_SIZE];
  memset(decrypted, 0, KEY_SIZE);
  assert_true(!bfe_bf_init_ciphertext(&ciphertext, &pk));
  assert_true(!bfe_bf_encaps(&ciphertext, K, &pk));
  assert_true(!bfe_bf_decaps(decrypted, &pk, &sk, &ciphertext));
  assert_true(!memcmp(K, decrypted, KEY_SIZE));

  bfe_bf_clear_secret_key(&sk);
  bfe_bf_clear_public_key(&pk);
  bfe_bf_clear_ciphertext(&ciphertext);
}

Ensure(BFE_BF, encrypt_decrypt_serialized) {
  bfe_bf_secret_key_t sk;
  bfe_bf_public_key_t pk;

  assert_true(!bfe_bf_init_secret_key(&sk));
  assert_true(!bfe_bf_init_public_key(&pk));
  assert_true(!bfe_bf_keygen(&pk, &sk, KEY_SIZE, 50, 0.001));

  bfe_bf_ciphertext_t ciphertext;
  bfe_bf_ciphertext_t deserialized_ciphertext;

  uint8_t K[KEY_SIZE], decrypted[KEY_SIZE];
  memset(decrypted, 0, KEY_SIZE);

  assert_true(!bfe_bf_init_ciphertext(&ciphertext, &pk));
  assert_true(!bfe_bf_encaps(&ciphertext, K, &pk));

  const size_t csize = bfe_bf_ciphertext_size(&ciphertext);
  uint8_t* bin       = malloc(csize);
  assert_true(bin != NULL);

  bfe_bf_ciphertext_serialize(bin, &ciphertext);
  assert_true(!bfe_bf_ciphertext_deserialize(&deserialized_ciphertext, bin));

  assert_true(!bfe_bf_decaps(decrypted, &pk, &sk, &deserialized_ciphertext));
  assert_true(!memcmp(K, decrypted, KEY_SIZE));

  free(bin);
  bfe_bf_clear_secret_key(&sk);
  bfe_bf_clear_public_key(&pk);
  bfe_bf_clear_ciphertext(&deserialized_ciphertext);
  bfe_bf_clear_ciphertext(&ciphertext);
}

Ensure(BFE_BF, decrypt_punctured) {
  bfe_bf_secret_key_t sk;
  bfe_bf_public_key_t pk;

  assert_true(!bfe_bf_init_secret_key(&sk));
  assert_true(!bfe_bf_init_public_key(&pk));
  assert_true(!bfe_bf_keygen(&pk, &sk, KEY_SIZE, 50, 0.001));

  bfe_bf_ciphertext_t ciphertext;

  uint8_t K[KEY_SIZE], decrypted[KEY_SIZE];
  memset(decrypted, 0, KEY_SIZE);

  assert_true(!bfe_bf_init_ciphertext(&ciphertext, &pk));
  assert_true(!bfe_bf_encaps(&ciphertext, K, &pk));
  bfe_bf_puncture(&sk, &ciphertext);

  assert_false(!bfe_bf_decaps(decrypted, &pk, &sk, &ciphertext));

  bfe_bf_clear_secret_key(&sk);
  bfe_bf_clear_public_key(&pk);
  bfe_bf_clear_ciphertext(&ciphertext);
}

Ensure(BFE_BF, keys_serialized) {
  bfe_bf_secret_key_t sk;
  bfe_bf_public_key_t pk;

  bfe_bf_secret_key_t deserialized_sk;
  bfe_bf_public_key_t deserialized_pk;

  assert_true(!bfe_bf_init_secret_key(&sk));
  assert_true(!bfe_bf_init_public_key(&pk));
  assert_true(!bfe_bf_keygen(&pk, &sk, KEY_SIZE, 50, 0.001));
  assert_true(!bfe_bf_init_public_key(&deserialized_pk));

  bfe_bf_ciphertext_t ciphertext;
  assert_true(!bfe_bf_init_ciphertext(&ciphertext, &pk));

  uint8_t* pk_bin = malloc(bfe_bf_public_key_size());
  bfe_bf_public_key_serialize(pk_bin, &pk);
  assert_true(!bfe_bf_public_key_deserialize(&deserialized_pk, pk_bin));
  free(pk_bin);

  uint8_t* sk_bin = malloc(bfe_bf_secret_key_size(&sk));
  bfe_bf_secret_key_serialize(sk_bin, &sk);
  assert_true(!bfe_bf_secret_key_deserialize(&deserialized_sk, sk_bin));
  free(sk_bin);

  uint8_t K[KEY_SIZE], decrypted[KEY_SIZE];
  memset(decrypted, 0, KEY_SIZE);

  assert_true(!bfe_bf_encaps(&ciphertext, K, &deserialized_pk));
  assert_true(!bfe_bf_decaps(decrypted, &pk, &sk, &ciphertext));
  assert_true(!memcmp(K, decrypted, KEY_SIZE));

  assert_true(!bfe_bf_encaps(&ciphertext, K, &pk));
  assert_true(!bfe_bf_decaps(decrypted, &pk, &deserialized_sk, &ciphertext));
  assert_true(!memcmp(K, decrypted, KEY_SIZE));

  bfe_bf_clear_ciphertext(&ciphertext);
  bfe_bf_clear_secret_key(&deserialized_sk);
  bfe_bf_clear_public_key(&deserialized_pk);
  bfe_bf_clear_secret_key(&sk);
  bfe_bf_clear_public_key(&pk);
}

int main() {
  TestSuite* suite = create_test_suite();
  add_test_with_context(suite, BFE_BF, encrypt_decrypt);
  add_test_with_context(suite, BFE_BF, encrypt_decrypt_serialized);
  add_test_with_context(suite, BFE_BF, decrypt_punctured);
  add_test_with_context(suite, BFE_BF, keys_serialized);
  return run_test_suite(suite, create_text_reporter());
}
