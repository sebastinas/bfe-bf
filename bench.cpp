#include <chrono>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "include/bfe-bf.h"
#include "include/tbfe-bbg.h"

using std::chrono::duration_cast;
using std::chrono::high_resolution_clock;
using std::chrono::microseconds;
using std::chrono::nanoseconds;

namespace std {
  template <>
  struct default_delete<bfe_bf_public_key_t> {
    constexpr default_delete() noexcept = default;

    void operator()(bfe_bf_public_key_t* ptr) const {
      bfe_bf_clear_public_key(ptr);
      delete ptr;
    }
  };

  template <>
  struct default_delete<bfe_bf_secret_key_t> {
    constexpr default_delete() noexcept = default;

    void operator()(bfe_bf_secret_key_t* ptr) const {
      bfe_bf_clear_secret_key(ptr);
      delete ptr;
    }
  };

  template <>
  struct default_delete<bfe_bf_ciphertext_t> {
    constexpr default_delete() noexcept = default;

    void operator()(bfe_bf_ciphertext_t* ptr) const {
      bfe_bf_clear_ciphertext(ptr);
      delete ptr;
    }
  };

  template <>
  struct default_delete<tbfe_bbg_public_key_t> {
    constexpr default_delete() noexcept = default;

    void operator()(tbfe_bbg_public_key_t* ptr) const {
      tbfe_bbg_clear_public_key(ptr);
      delete ptr;
    }
  };

  template <>
  struct default_delete<tbfe_bbg_secret_key_t> {
    constexpr default_delete() noexcept = default;

    void operator()(tbfe_bbg_secret_key_t* ptr) const {
      tbfe_bbg_clear_secret_key(ptr);
      delete ptr;
    }
  };

  template <>
  struct default_delete<tbfe_bbg_ciphertext_t> {
    constexpr default_delete() noexcept = default;

    void operator()(tbfe_bbg_ciphertext_t* ptr) const {
      tbfe_bbg_clear_ciphertext(ptr);
      delete ptr;
    }
  };
} // namespace std

namespace {
  constexpr unsigned int REPEATS       = 50;
  constexpr double FALSE_POSITIVE_PROB = 1.0 / (1 << 10);

  template <class T, class I, class... Args>
  auto make_holder(I i, Args&&... args) {
    std::unique_ptr<T> h{new T};
    i(h.get(), std::forward<Args>(args)...);
    return h;
  }

  template <class Duration>
  std::string beautify_duration(Duration input_duration) {
    using std::chrono::hours;
    using std::chrono::milliseconds;
    using std::chrono::minutes;
    using std::chrono::seconds;

    auto h = duration_cast<hours>(input_duration);
    input_duration -= h;
    auto m = duration_cast<minutes>(input_duration);
    input_duration -= m;
    auto s = duration_cast<seconds>(input_duration);
    input_duration -= s;
    auto ms = duration_cast<milliseconds>(input_duration);
    input_duration -= ms;
    auto micros = duration_cast<microseconds>(input_duration);

    auto hc      = h.count();
    auto mc      = m.count();
    auto sc      = s.count();
    auto msc     = ms.count();
    auto microsc = micros.count();

    std::stringstream ss;
    ss.fill('0');
    if (hc) {
      ss << hc << 'h';
    }
    if (hc || mc) {
      if (hc) {
        ss << std::setw(2);
      }
      ss << mc << 'm';
    }
    if (hc || mc || sc) {
      if (hc || mc) {
        ss << std::setw(2);
      }
      ss << sc << 's';
    }
    if (hc || mc || sc || msc) {
      if (hc || mc || sc) {
        ss << std::setw(3);
      }
      ss << msc << "ms";
    }
    if (hc || mc || sc || msc || microsc) {
      if (hc || mc || sc || msc) {
        ss << std::setw(3);
      }
      ss << microsc << "µs";
    }

    return ss.str();
  }


  // ### BFE BENCHMARK
  void bench_bfe() {
    auto sk = make_holder<bfe_bf_secret_key_t>(bfe_bf_init_secret_key);
    auto pk = make_holder<bfe_bf_public_key_t>(bfe_bf_init_public_key);

    auto start_time = high_resolution_clock::now();
    /* n=2^19 >= 2^12 per day for 3 months, correctness error ~ 2^-10 */
    static constexpr unsigned int bloom_filter_size = 1 << 19;
    bfe_bf_keygen(pk.get(), sk.get(), 32, bloom_filter_size, FALSE_POSITIVE_PROB);
    auto keygen_time = high_resolution_clock::now() - start_time;
    std::cout << "bfe keygen:           " << duration_cast<microseconds>(keygen_time).count()
              << " µs" << std::endl;
    std::cout << "bfe key parameters:" << std::endl;
    std::cout << "    hash functions:   " << pk.get()->filter_hash_count << std::endl;
    std::cout << "    num elements:     " << bloom_filter_size << std::endl;
    std::cout << "    bloomfilter size: " << pk.get()->filter_size << std::endl;
    std::cout << "    correctness err:  " << FALSE_POSITIVE_PROB << std::endl;

    nanoseconds encaps_time{0};
    for (unsigned int i = 0; i < REPEATS; ++i) {
      uint8_t K[32];
      auto ciphertext = make_holder<bfe_bf_ciphertext_t>(bfe_bf_init_ciphertext, pk.get());

      start_time = high_resolution_clock::now();
      bfe_bf_encaps(ciphertext.get(), K, pk.get());
      encaps_time += high_resolution_clock::now() - start_time;
    }
    std::cout << "bfe encaps:           "
              << duration_cast<microseconds>(encaps_time / REPEATS).count() << " µs - "
              << beautify_duration(encaps_time / REPEATS) << std::endl;

    nanoseconds decaps_time{0};
    for (unsigned int i = 0; i < REPEATS; ++i) {
      uint8_t K[32];
      auto ciphertext = make_holder<bfe_bf_ciphertext_t>(bfe_bf_init_ciphertext, pk.get());
      bfe_bf_encaps(ciphertext.get(), K, pk.get());

      uint8_t decrypted[32];
      start_time = high_resolution_clock::now();
      bfe_bf_decaps(decrypted, pk.get(), sk.get(), ciphertext.get());
      decaps_time += high_resolution_clock::now() - start_time;
    }
    std::cout << "bfe decaps:           "
              << duration_cast<microseconds>(decaps_time / REPEATS).count() << " µs - "
              << beautify_duration(decaps_time / REPEATS) << std::endl;

    nanoseconds punc_time{0};
    for (unsigned int i = 0; i < REPEATS; ++i) {
      uint8_t K[32];
      auto ciphertext = make_holder<bfe_bf_ciphertext_t>(bfe_bf_init_ciphertext, pk.get());
      bfe_bf_encaps(ciphertext.get(), K, pk.get());

      start_time = high_resolution_clock::now();
      bfe_bf_puncture(sk.get(), ciphertext.get());
      punc_time += high_resolution_clock::now() - start_time;
    }
    std::cout << "bfe punc:             "
              << duration_cast<microseconds>(punc_time / REPEATS).count() << " µs - "
              << beautify_duration(punc_time / REPEATS) << std::endl;
  }


  // ### TBFE BENCHMARK
  void bench_tbfe() {
    std::cout << "Running 'bench_tbfe' ... " << std::endl; 

    /* n=2^9, depth = 2^10 =>  2 * 2^9 per day for 17 months, correctness error ~ 2^-10 */
    constexpr unsigned int bloom_filter_size = 1 << 9;
    constexpr unsigned int total_depth       = 10 + 2;

    // key pair for time-interval 1
    auto sk = make_holder<tbfe_bbg_secret_key_t>(tbfe_bbg_init_secret_key, bloom_filter_size, FALSE_POSITIVE_PROB);
    auto pk = make_holder<tbfe_bbg_public_key_t>(tbfe_bbg_init_public_key, total_depth);

    // key pair for time-interval 10 (e.g. leaf)
    auto sk_leaf = make_holder<tbfe_bbg_secret_key_t>(tbfe_bbg_init_secret_key, bloom_filter_size, FALSE_POSITIVE_PROB);
    auto pk_leaf = make_holder<tbfe_bbg_public_key_t>(tbfe_bbg_init_public_key, total_depth);
    /* generate keys and puncture 'leaf secret key' 10 times */
    tbfe_bbg_keygen(pk_leaf.get(), sk_leaf.get());
    for (unsigned int i = 2; i <= 10; i++)
    {
      tbfe_bbg_puncture_interval(sk_leaf.get(), pk_leaf.get(), i);
    }
    
    
    /* benchmark key generation */
    auto start_time = high_resolution_clock::now();
    tbfe_bbg_keygen(pk.get(), sk.get());
    auto keygen_time = high_resolution_clock::now() - start_time;
    std::cout << "tbfe keygen:          " << duration_cast<microseconds>(keygen_time).count()
              << " µs - " << beautify_duration(keygen_time) << std::endl;
    std::cout << "tbfe key parameters:" << std::endl;
    std::cout << "    hash functions:   " << pk.get()->bloom_filter_hashes << std::endl;
    std::cout << "    num elements:     " << bloom_filter_size << std::endl;
    std::cout << "    bloomfilter size: " << pk.get()->bloom_filter_size << std::endl;
    std::cout << "    correctness err:  " << FALSE_POSITIVE_PROB << std::endl;

    std::cout << "\n<< BENCHMARKS (runtime as average of " << REPEATS << " runs) >>" << std::endl;

    /* benchmark encaps */
    nanoseconds encaps_time{0};
    for (unsigned int i = 0; i < REPEATS; ++i) {
      uint8_t K[SECURITY_PARAMETER];
      auto ciphertext = make_holder<tbfe_bbg_ciphertext_t>(tbfe_bbg_init_ciphertext);

      start_time = high_resolution_clock::now();
      tbfe_bbg_encaps(K, ciphertext.get(), pk.get(), 1);
      encaps_time += high_resolution_clock::now() - start_time;
    }
    std::cout << "tbfe encaps:          "
              << duration_cast<microseconds>(encaps_time / REPEATS).count() << " µs - "
              << beautify_duration(encaps_time / REPEATS) << std::endl;

    /* benchmark encaps + serialization */
    nanoseconds encaps_serialize_time{0};
    std::vector<uint8_t> serialized_ciphertext;
    for (unsigned int i = 0; i < REPEATS; ++i) {
      uint8_t K[SECURITY_PARAMETER];
      auto ciphertext = make_holder<tbfe_bbg_ciphertext_t>(tbfe_bbg_init_ciphertext);

      start_time = high_resolution_clock::now();
      tbfe_bbg_encaps(K, ciphertext.get(), pk.get(), 1);
      serialized_ciphertext.resize(tbfe_bbg_ciphertext_size(ciphertext.get()));
      tbfe_bbg_ciphertext_serialize(serialized_ciphertext.data(), ciphertext.get());
      encaps_serialize_time += high_resolution_clock::now() - start_time;
    }
    std::cout << "tbfe encaps (+ ser):  "
              << duration_cast<microseconds>(encaps_serialize_time / REPEATS).count() << " µs - "
              << beautify_duration(encaps_serialize_time / REPEATS) << std::endl;

    /* benchmark encaps leaf*/
    nanoseconds encaps_leaf_time{0};
    for (unsigned int i = 0; i < REPEATS; ++i) {
      uint8_t K[SECURITY_PARAMETER];
      auto ciphertext = make_holder<tbfe_bbg_ciphertext_t>(tbfe_bbg_init_ciphertext);

      start_time = high_resolution_clock::now();
      tbfe_bbg_encaps(K, ciphertext.get(), pk_leaf.get(), 10);
      encaps_leaf_time += high_resolution_clock::now() - start_time;
    }
    std::cout << "tbfe encaps (leaf):   "
              << duration_cast<microseconds>(encaps_leaf_time / REPEATS).count() << " µs - "
              << beautify_duration(encaps_leaf_time / REPEATS) << std::endl;

    /* benchmark decaps */
    nanoseconds decaps_time{0};
    for (unsigned int i = 0; i < REPEATS; ++i) {
      uint8_t K[SECURITY_PARAMETER], Kd[SECURITY_PARAMETER];
      auto ciphertext = make_holder<tbfe_bbg_ciphertext_t>(tbfe_bbg_init_ciphertext);

      tbfe_bbg_encaps(K, ciphertext.get(), pk.get(), 1);
      start_time = high_resolution_clock::now();
      tbfe_bbg_decaps(Kd, ciphertext.get(), sk.get(), pk.get());
      decaps_time += high_resolution_clock::now() - start_time;
    }
    std::cout << "tbfe decaps:          "
              << duration_cast<microseconds>(decaps_time / REPEATS).count() << " µs - "
              << beautify_duration(decaps_time / REPEATS) << std::endl;

    /* benchmark decaps + serialization */
    nanoseconds decaps_serialize_time{0};
    for (unsigned int i = 0; i < REPEATS; ++i) {
      uint8_t K[SECURITY_PARAMETER], Kd[SECURITY_PARAMETER];

      {
        auto ciphertext = make_holder<tbfe_bbg_ciphertext_t>(tbfe_bbg_init_ciphertext);
        tbfe_bbg_encaps(K, ciphertext.get(), pk.get(), 1);
        serialized_ciphertext.resize(tbfe_bbg_ciphertext_size(ciphertext.get()));
        tbfe_bbg_ciphertext_serialize(serialized_ciphertext.data(), ciphertext.get());
      }

      start_time      = high_resolution_clock::now();
      auto ciphertext = make_holder<tbfe_bbg_ciphertext_t>(tbfe_bbg_ciphertext_deserialize,
                                                           serialized_ciphertext.data());

      tbfe_bbg_decaps(Kd, ciphertext.get(), sk.get(), pk.get());
      decaps_serialize_time += high_resolution_clock::now() - start_time;
    }
    std::cout << "tbfe decaps (+ ser):  "
              << duration_cast<microseconds>(decaps_serialize_time / REPEATS).count() << " µs - "
              << beautify_duration(decaps_serialize_time / REPEATS) << std::endl;
    
     /* benchmark decaps leaf */
    nanoseconds decaps_leaf_time{0};
    for (unsigned int i = 0; i < REPEATS; ++i) {
      uint8_t K[SECURITY_PARAMETER], Kd[SECURITY_PARAMETER];
      auto ciphertext = make_holder<tbfe_bbg_ciphertext_t>(tbfe_bbg_init_ciphertext);

      tbfe_bbg_encaps(K, ciphertext.get(), pk_leaf.get(), 10);
      start_time = high_resolution_clock::now();
      tbfe_bbg_decaps(Kd, ciphertext.get(), sk_leaf.get(), pk_leaf.get());
      decaps_leaf_time += high_resolution_clock::now() - start_time;
    }
    std::cout << "tbfe decaps (leaf):   "
              << duration_cast<microseconds>(decaps_leaf_time / REPEATS).count() << " µs - "
              << beautify_duration(decaps_leaf_time / REPEATS) << std::endl;


    /* benchmark puncture ctx */
    nanoseconds punc_time{0};
    for (unsigned int i = 0; i < REPEATS; ++i) {
      uint8_t K[SECURITY_PARAMETER];
      auto ciphertext = make_holder<tbfe_bbg_ciphertext_t>(tbfe_bbg_init_ciphertext);

      tbfe_bbg_encaps(K, ciphertext.get(), pk.get(), 1);
      start_time = high_resolution_clock::now();
      tbfe_bbg_puncture_ciphertext(sk.get(), ciphertext.get());
      punc_time += high_resolution_clock::now() - start_time;
    }
    std::cout << "tbfe punc:            "
              << duration_cast<microseconds>(punc_time / REPEATS).count() << " µs - "
              << beautify_duration(punc_time / REPEATS) << std::endl;

    /* benchmark puncture interval */
    nanoseconds punc_interval_time{0};
    unsigned int time_interval = 1;
    for (unsigned int i = 0; i < REPEATS; ++i, ++time_interval) {
      start_time = high_resolution_clock::now();
      tbfe_bbg_puncture_interval(sk.get(), pk.get(), time_interval);
      punc_interval_time += high_resolution_clock::now() - start_time;
    }
    std::cout << "tbfe punc (interval): "
              << duration_cast<microseconds>(punc_interval_time / REPEATS).count() << " µs - "
              << beautify_duration(punc_interval_time / REPEATS) << std::endl;
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
