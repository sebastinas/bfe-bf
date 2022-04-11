#include <chrono>
#include <iostream>
#include <string>
#include <vector>

#include "include/bfe-bf.h"
#include "include/tbfe-bbg.h"

using std::chrono::duration_cast;
using std::chrono::high_resolution_clock;
using std::chrono::microseconds;

namespace {
  constexpr unsigned int REPEATS = 50;

  void bench_bfe() {
    bfe_bf_secret_key_t sk;
    bfe_bf_public_key_t pk;

    bfe_bf_init_secret_key(&sk);
    bfe_bf_init_public_key(&pk);
    auto start_time = high_resolution_clock::now();
    /* n=2^19 >= 2^12 per day for 3 months, correctness error ~ 2^-10 */
    bfe_bf_keygen(&pk, &sk, 32, 1 << 19, 0.0009765625);
    auto keygen_time = duration_cast<microseconds>(high_resolution_clock::now() - start_time);

    bfe_bf_ciphertext_t ciphertext;
    bfe_bf_init_ciphertext(&ciphertext, &pk);

    uint8_t K[32];
    microseconds encaps_time{0};
    for (unsigned int i = 0; i < REPEATS; ++i) {
      start_time = high_resolution_clock::now();
      bfe_bf_encaps(&ciphertext, K, &pk);
      encaps_time += duration_cast<microseconds>(high_resolution_clock::now() - start_time);
    }

    microseconds decaps_time{0};
    for (unsigned int i = 0; i < REPEATS; ++i) {
      bfe_bf_encaps(&ciphertext, K, &pk);

      uint8_t decrypted[32];
      start_time = high_resolution_clock::now();
      bfe_bf_decaps(decrypted, &pk, &sk, &ciphertext);
      decaps_time += duration_cast<microseconds>(high_resolution_clock::now() - start_time);
    }

    microseconds punc_time{0};
    for (unsigned int i = 0; i < REPEATS; ++i) {
      bfe_bf_encaps(&ciphertext, K, &pk);
      start_time = high_resolution_clock::now();
      bfe_bf_puncture(&sk, &ciphertext);
      punc_time += duration_cast<microseconds>(high_resolution_clock::now() - start_time);
    }

    bfe_bf_clear_secret_key(&sk);
    bfe_bf_clear_public_key(&pk);
    bfe_bf_clear_ciphertext(&ciphertext);

    std::cout << "bfe keygen: " << keygen_time.count() << " ms\n";
    std::cout << "bfe encaps: " << encaps_time.count() / REPEATS << " ms\n";
    std::cout << "bfe decaps: " << decaps_time.count() / REPEATS << " ms\n";
    std::cout << "bfe punc:   " << punc_time.count() / REPEATS << " ms\n";
  }

  void bench_tbfe() {
    /* TODO: use sensible parameters */
    constexpr unsigned int number_hash_functions = 4;
    constexpr unsigned int bloom_filter_size     = 1000;
    constexpr unsigned int cellsize              = 4;
    constexpr unsigned int total_levels          = 4;
    constexpr unsigned int total_depth           = total_levels + 2;

    tbfe_bbg_secret_key_t sk;
    tbfe_bbg_public_key_t pk;

    /* benchmark key generation */
    tbfe_bbg_init_public_key(&pk, total_depth);
    tbfe_bbg_init_secret_key(&sk, bloom_filter_size, cellsize, number_hash_functions);
    auto start_time = high_resolution_clock::now();
    tbfe_bbg_keygen(&pk, &sk, bloom_filter_size, number_hash_functions, total_levels);
    auto keygen_time = duration_cast<microseconds>(high_resolution_clock::now() - start_time);

    /* benchmark encaps */
    microseconds encaps_time{0};
    for (unsigned int i = 0; i < REPEATS; ++i) {
      uint8_t K[SECURITY_PARAMETER];
      tbfe_bbg_ciphertext_t ciphertext;
      tbfe_bbg_init_ciphertext(&ciphertext);
      start_time = high_resolution_clock::now();
      tbfe_bbg_encaps(K, &ciphertext, &pk, 1);
      encaps_time += duration_cast<microseconds>(high_resolution_clock::now() - start_time);
      tbfe_bbg_clear_ciphertext(&ciphertext);
    }
    /* benchmark encaps + serialization */
    microseconds encaps_serialize_time{0};
    std::vector<uint8_t> serialized_ciphertext;
    for (unsigned int i = 0; i < REPEATS; ++i) {
      uint8_t K[SECURITY_PARAMETER];
      tbfe_bbg_ciphertext_t ciphertext;
      tbfe_bbg_init_ciphertext(&ciphertext);
      start_time = high_resolution_clock::now();
      tbfe_bbg_encaps(K, &ciphertext, &pk, 1);
      serialized_ciphertext.resize(tbfe_bbg_get_ciphertext_size(&ciphertext));
      tbfe_bbg_serialize_ciphertext(serialized_ciphertext.data(), &ciphertext);
      encaps_serialize_time +=
          duration_cast<microseconds>(high_resolution_clock::now() - start_time);
      tbfe_bbg_clear_ciphertext(&ciphertext);
    }

    /* benchmark decaps */
    microseconds decaps_time{0};
    for (unsigned int i = 0; i < REPEATS; ++i) {
      uint8_t K[SECURITY_PARAMETER], Kd[SECURITY_PARAMETER];
      tbfe_bbg_ciphertext_t ciphertext;
      tbfe_bbg_init_ciphertext(&ciphertext);
      tbfe_bbg_encaps(K, &ciphertext, &pk, 1);
      start_time = high_resolution_clock::now();
      tbfe_bbg_decaps(Kd, &ciphertext, &sk, &pk);
      decaps_time += duration_cast<microseconds>(high_resolution_clock::now() - start_time);
      tbfe_bbg_clear_ciphertext(&ciphertext);
    }
    microseconds decaps_serialize_time{0};
    for (unsigned int i = 0; i < REPEATS; ++i) {
      uint8_t K[SECURITY_PARAMETER], Kd[SECURITY_PARAMETER];
      tbfe_bbg_ciphertext_t ciphertext;
      tbfe_bbg_init_ciphertext(&ciphertext);
      tbfe_bbg_encaps(K, &ciphertext, &pk, 1);
      serialized_ciphertext.resize(tbfe_bbg_get_ciphertext_size(&ciphertext));
      tbfe_bbg_serialize_ciphertext(serialized_ciphertext.data(), &ciphertext);
      tbfe_bbg_clear_ciphertext(&ciphertext);

      start_time = high_resolution_clock::now();
      tbfe_bbg_init_ciphertext_from_serialized(&ciphertext, serialized_ciphertext.data());
      tbfe_bbg_decaps(Kd, &ciphertext, &sk, &pk);
      decaps_serialize_time +=
          duration_cast<microseconds>(high_resolution_clock::now() - start_time);

      tbfe_bbg_clear_ciphertext(&ciphertext);
    }

    microseconds punc_time{0};
    for (unsigned int i = 0; i < REPEATS; ++i) {
      uint8_t K[SECURITY_PARAMETER];
      tbfe_bbg_ciphertext_t ciphertext;
      tbfe_bbg_init_ciphertext(&ciphertext);
      tbfe_bbg_encaps(K, &ciphertext, &pk, 1);
      start_time = high_resolution_clock::now();
      tbfe_bbg_puncture_ciphertext(&sk, &ciphertext);
      punc_time += duration_cast<microseconds>(high_resolution_clock::now() - start_time);
      tbfe_bbg_clear_ciphertext(&ciphertext);
    }

    microseconds punc_interval_time{0};
    unsigned int time_interval = 1;
    for (unsigned int i = 0; i < REPEATS; ++i, ++time_interval) {
      start_time = high_resolution_clock::now();
      tbfe_bbg_puncture_interval(&sk, &pk, time_interval);
      punc_interval_time += duration_cast<microseconds>(high_resolution_clock::now() - start_time);
    }

    tbfe_bbg_clear_secret_key(&sk);
    tbfe_bbg_clear_public_key(&pk);

    std::cout << "tbfe keygen:          " << keygen_time.count() << " ms\n";
    std::cout << "tbfe encaps:          " << encaps_time.count() / REPEATS << " ms\n";
    std::cout << "tbfe encaps (+ ser):  " << encaps_serialize_time.count() / REPEATS << " ms\n";
    std::cout << "tbfe decaps:          " << decaps_time.count() / REPEATS << " ms\n";
    std::cout << "tbfe decaps (+ ser):  " << decaps_serialize_time.count() / REPEATS << " ms\n";
    std::cout << "tbfe punc:            " << punc_time.count() / REPEATS << " ms\n";
    std::cout << "tbfe punc (interval): " << punc_interval_time.count() / REPEATS << " ms\n";
  }
} // namespace

int main(int argc, char** argv) {
  if (argc <= 1) {
    bench_bfe();
    bench_tbfe();
    return 0;
  }

  for (int i = 1; i < argc; ++i) {
    std::string arg{argv[i]};
    if (arg == "bfe") {
      bench_bfe();
    } else if (arg == "tbfe") {
      bench_tbfe();
    } else {
      std::cout << "Unknown benchmark: " << argv[i] << " - valid benchmarks are 'bfe' and 'tbfe'."
                << std::endl;
      return 1;
    }
  }

  return 0;
}
