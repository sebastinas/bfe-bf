#include "../include/crypto_api.h"

#include <cgreen/cgreen.h>

Describe(API);
BeforeEach(API) {}
AfterEach(API) {}

Ensure(API, encrypt_decrypt_puncture) {
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];
  unsigned char* sk = malloc(CRYPTO_SECRETKEYBYTES);
  unsigned char k[CRYPTO_BYTES], k2[CRYPTO_BYTES];
  unsigned char ct[CRYPTO_CIPHERTEXTBYTES];

  assert_true(!crypto_kem_keypair(pk, sk));
  assert_true(!crypto_kem_enc(ct, k, pk));
  assert_true(!crypto_kem_dec(k2, ct, sk));
  assert_true(memcmp(k, k2, CRYPTO_BYTES) == 0);

  assert_true(!crypto_kem_punc(sk, ct));
  assert_false(!crypto_kem_dec(k2, ct, sk));

  free(sk);
}

int main() {
  TestSuite* suite = create_test_suite();
  add_test_with_context(suite, API, encrypt_decrypt_puncture);
  return run_test_suite(suite, create_text_reporter());
}
