#include <relic/relic_conf.h>
/* Because relic hardcodes too much stuff ... */
#undef BENCH
#define BENCH 50
#include <relic/relic_bench.h>

#include <string.h>

#include "include/bfe-bf.h"

static void bench_bfe(void) {
  bfe_bf_secret_key_t sk;
  bfe_bf_public_key_t pk;

  bfe_bf_init_secret_key(&sk);
  bfe_bf_init_public_key(&pk);
  /* n=2^19 >= 2^12 per day for 3 months, correctness error ~ 2^-10 */
  BENCH_ONCE("keygen", bfe_bf_keygen(&pk, &sk, 32, 1 << 19, 0.0009765625));

  bfe_bf_ciphertext_t ciphertext;
  bfe_bf_init_ciphertext(&ciphertext, &pk);

  uint8_t K[32], decrypted[32];
  BENCH_BEGIN("encrypt") {
    BENCH_ADD(bfe_bf_encaps(&ciphertext, K, &pk));
  }
  BENCH_END;
  BENCH_BEGIN("decrypt") {
    bfe_bf_encaps(&ciphertext, K, &pk);
    memset(decrypted, 0, pk.key_size);
    BENCH_ADD(bfe_bf_decaps(decrypted, &pk, &sk, &ciphertext));
  }
  BENCH_END;
  BENCH_BEGIN("puncture") {
    bfe_bf_encaps(&ciphertext, K, &pk);
    BENCH_ADD(bfe_bf_puncture(&sk, &ciphertext));
  }
  BENCH_END;

  bfe_bf_clear_secret_key(&sk);
  bfe_bf_clear_public_key(&pk);
  bfe_bf_clear_ciphertext(&ciphertext);
}

int main() {
  bench_bfe();
  return 0;
}
