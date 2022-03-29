#include <relic/relic_conf.h>
/* Because relic hardcodes too much stuff ... */
#undef BENCH
#define BENCH 50
#include <relic/relic_bench.h>

#include <string.h>

#include "include/bfe-bf.h"
#include "include/tbfe-bbg.h"

static void bench_bfe(void) {
  bfe_bf_secret_key_t sk;
  bfe_bf_public_key_t pk;

  bfe_bf_init_secret_key(&sk);
  bfe_bf_init_public_key(&pk);
  /* n=2^19 >= 2^12 per day for 3 months, correctness error ~ 2^-10 */
  BENCH_ONCE("bfe keygen", bfe_bf_keygen(&pk, &sk, 32, 1 << 19, 0.0009765625));

  bfe_bf_ciphertext_t ciphertext;
  bfe_bf_init_ciphertext(&ciphertext, &pk);

  uint8_t K[32], decrypted[32];
  BENCH_BEGIN("bfe encaps") {
    BENCH_ADD(bfe_bf_encaps(&ciphertext, K, &pk));
  }
  BENCH_END;
  BENCH_BEGIN("bfe decaps") {
    bfe_bf_encaps(&ciphertext, K, &pk);
    memset(decrypted, 0, pk.key_size);
    BENCH_ADD(bfe_bf_decaps(decrypted, &pk, &sk, &ciphertext));
  }
  BENCH_END;
  BENCH_BEGIN("bfe punc") {
    bfe_bf_encaps(&ciphertext, K, &pk);
    BENCH_ADD(bfe_bf_puncture(&sk, &ciphertext));
  }
  BENCH_END;

  bfe_bf_clear_secret_key(&sk);
  bfe_bf_clear_public_key(&pk);
  bfe_bf_clear_ciphertext(&ciphertext);
}

static void bench_tbfe(void) {
  /* TODO: use sensible parameters */
  static const unsigned int number_hash_functions = 4;
  static const unsigned int bloom_filter_size     = 1000;
  static const unsigned int cellsize              = 4;
  static const unsigned int total_levels          = 4;
  static const unsigned int total_depth           = total_levels + 2;

  tbfe_bbg_secret_key_t sk;
  tbfe_bbg_public_key_t pk;

  /* benchmark key generation */
  tbfe_bbg_init_public_key(&pk, total_depth);
  tbfe_bbg_init_secret_key(&sk, bloom_filter_size, cellsize, number_hash_functions);
  BENCH_ONCE("tbfe keygen",
             tbfe_bbg_keygen(&pk, &sk, bloom_filter_size, number_hash_functions, total_levels));

  /* benchmark encaps */
  BENCH_BEGIN("tbfe encaps") {
    uint8_t K[SECURITY_PARAMETER];
    tbfe_bbg_ciphertext_t ciphertext;
    tbfe_bbg_init_ciphertext(&ciphertext);
    BENCH_ADD(tbfe_bbg_encaps(K, &ciphertext, &pk, 1));
    tbfe_bbg_clear_ciphertext(&ciphertext);
  }
  BENCH_END;
  /* benchmark encaps + serialization */
  BENCH_BEGIN("tbfe encaps + serialization") {
    uint8_t K[SECURITY_PARAMETER];
    tbfe_bbg_ciphertext_t ciphertext;
    uint8_t* serialized_ciphertext = NULL;
    tbfe_bbg_init_ciphertext(&ciphertext);
    BENCH_ADD(do {
      tbfe_bbg_encaps(K, &ciphertext, &pk, 1);
      serialized_ciphertext = malloc(tbfe_bbg_get_ciphertext_size(&ciphertext));
      tbfe_bbg_serialize_ciphertext(serialized_ciphertext, &ciphertext);
    } while (0));
    free(serialized_ciphertext);
    tbfe_bbg_clear_ciphertext(&ciphertext);
  }
  BENCH_END;

  /* benchmark decaps */
  BENCH_BEGIN("tbfe decaps") {
    uint8_t K[SECURITY_PARAMETER], Kd[SECURITY_PARAMETER];
    tbfe_bbg_ciphertext_t ciphertext;
    tbfe_bbg_init_ciphertext(&ciphertext);
    tbfe_bbg_encaps(K, &ciphertext, &pk, 1);
    BENCH_ADD(tbfe_bbg_decaps(Kd, &ciphertext, &sk, &pk));
    tbfe_bbg_clear_ciphertext(&ciphertext);
  }
  BENCH_END;
  BENCH_BEGIN("tbfe decaps + serialization") {
    uint8_t K[SECURITY_PARAMETER], Kd[SECURITY_PARAMETER];
    tbfe_bbg_ciphertext_t ciphertext;
    tbfe_bbg_init_ciphertext(&ciphertext);
    tbfe_bbg_encaps(K, &ciphertext, &pk, 1);
    uint8_t* serialized_ciphertext = malloc(tbfe_bbg_get_ciphertext_size(&ciphertext));
    tbfe_bbg_serialize_ciphertext(serialized_ciphertext, &ciphertext);
    tbfe_bbg_clear_ciphertext(&ciphertext);

    BENCH_ADD(do {
      tbfe_bbg_init_ciphertext_from_serialized(&ciphertext, serialized_ciphertext);
      tbfe_bbg_decaps(Kd, &ciphertext, &sk, &pk);
    } while (0));
    tbfe_bbg_clear_ciphertext(&ciphertext);
    free(serialized_ciphertext);
  }
  BENCH_END;

  BENCH_BEGIN("tbfe punc ctxt") {
    uint8_t K[SECURITY_PARAMETER];
    tbfe_bbg_ciphertext_t ciphertext;
    tbfe_bbg_init_ciphertext(&ciphertext);
    tbfe_bbg_encaps(K, &ciphertext, &pk, 1);
    BENCH_ADD(tbfe_bbg_puncture_ciphertext(&sk, &ciphertext));
    tbfe_bbg_clear_ciphertext(&ciphertext);
  }
  BENCH_END;

  unsigned int time_interval = 1;
  BENCH_BEGIN("tbfe punc interval") {
    BENCH_ADD(tbfe_bbg_puncture_interval(&sk, &pk, time_interval++));
  }
  BENCH_END;

  tbfe_bbg_clear_secret_key(&sk);
  tbfe_bbg_clear_public_key(&pk);
}

int main(int argc, char** argv) {
  if (argc <= 1) {
    bench_bfe();
    bench_tbfe();
    return 0;
  }

  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "bfe")) {
      bench_bfe();
    } else if (!strcmp(argv[i], "tbfe")) {
      bench_tbfe();
    } else {
      printf("Unknown benchmark: %s - valid benchmarks are bfe and tbfe.\n", argv[i]);
      return 1;
    }
  }

  return 0;
}
