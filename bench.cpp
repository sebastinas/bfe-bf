#include <config.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <cxxopts.hpp>

#include "vector.h"

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
  constexpr unsigned int REPEATS = 50;
  constexpr unsigned int WARMUP  = 5;

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
  void bench_bfe(unsigned int bloom_filter_size, double false_positive_prob) {
    auto sk = make_holder<bfe_bf_secret_key_t>(bfe_bf_init_secret_key);
    auto pk = make_holder<bfe_bf_public_key_t>(bfe_bf_init_public_key);

    auto start_time = high_resolution_clock::now();
    bfe_bf_keygen(pk.get(), sk.get(), 32, bloom_filter_size, false_positive_prob);
    auto keygen_time = high_resolution_clock::now() - start_time;
    std::cout << "bfe keygen:           " << duration_cast<microseconds>(keygen_time).count()
              << " µs" << std::endl;
    std::cout << "bfe key parameters:" << std::endl;
    std::cout << "    hash functions:   " << pk.get()->filter_hash_count << std::endl;
    std::cout << "    num elements:     " << bloom_filter_size << std::endl;
    std::cout << "    bloomfilter size: " << pk.get()->filter_size << std::endl;
    std::cout << "    correctness err:  " << false_positive_prob << std::endl;

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
  void bench_tbfe(unsigned int bloom_filter_size, double false_positive_prob, unsigned int height) {
    std::cout << "Running 'bench_tbfe' ...\n" << std::endl;

    /* n=2^9, depth = 2^10 =>  2 * 2^9 per day for 17 months, correctness error ~ 2^-10 */
    unsigned int total_depth = height + 2;

    // key pair for time-interval 1
    auto sk = make_holder<tbfe_bbg_secret_key_t>(tbfe_bbg_init_secret_key, bloom_filter_size,
                                                 false_positive_prob);
    auto pk = make_holder<tbfe_bbg_public_key_t>(tbfe_bbg_init_public_key, total_depth);

    // key pair for time-interval 10 (e.g. leaf)
    auto sk_leaf = make_holder<tbfe_bbg_secret_key_t>(tbfe_bbg_init_secret_key, bloom_filter_size,
                                                      false_positive_prob);
    auto pk_leaf = make_holder<tbfe_bbg_public_key_t>(tbfe_bbg_init_public_key, total_depth);
    /* generate keys and puncture 'leaf secret key' 10 times */
    tbfe_bbg_keygen(pk_leaf.get(), sk_leaf.get());
    for (unsigned int i = 2; i <= 10; i++) {
      tbfe_bbg_puncture_interval(sk_leaf.get(), pk_leaf.get(), i);
    }

    /* benchmark key generation */
    auto start_time = high_resolution_clock::now();
    tbfe_bbg_keygen(pk.get(), sk.get());
    auto end_time    = high_resolution_clock::now();
    auto keygen_time = end_time - start_time;
    std::cout << "tbfe keygen:          " << duration_cast<microseconds>(keygen_time).count()
              << " µs - " << beautify_duration(keygen_time) << std::endl;
    std::cout << "tbfe key parameters:" << std::endl;
    std::cout << "    hash functions:   " << pk.get()->bloom_filter_hashes << std::endl;
    std::cout << "    num elements:     " << bloom_filter_size << std::endl;
    std::cout << "    bloomfilter size: " << pk.get()->bloom_filter_size << std::endl;
    std::cout << "    correctness err:  " << false_positive_prob << std::endl;

    std::cout << "\n<< BENCHMARKS (runtime as average of " << REPEATS << " runs) >>" << std::endl;

    /* benchmark encaps */
    nanoseconds encaps_time{0};
    for (unsigned int i = 0; i < (REPEATS + WARMUP); ++i) {
      uint8_t K[SECURITY_PARAMETER];
      auto ciphertext = make_holder<tbfe_bbg_ciphertext_t>(tbfe_bbg_init_ciphertext);

      start_time = high_resolution_clock::now();
      tbfe_bbg_encaps(K, ciphertext.get(), pk.get(), 1);
      end_time = high_resolution_clock::now();
      if (i >= WARMUP) {
        encaps_time += end_time - start_time;
      }
    }
    std::cout << "tbfe encaps:          "
              << duration_cast<microseconds>(encaps_time / REPEATS).count() << " µs - "
              << beautify_duration(encaps_time / REPEATS) << std::endl;

    /* benchmark encaps + serialization */
    nanoseconds encaps_serialize_time{0};
    std::vector<uint8_t> serialized_ciphertext;
    for (unsigned int i = 0; i < (REPEATS + WARMUP); ++i) {
      uint8_t K[SECURITY_PARAMETER];
      auto ciphertext = make_holder<tbfe_bbg_ciphertext_t>(tbfe_bbg_init_ciphertext);

      start_time = high_resolution_clock::now();
      tbfe_bbg_encaps(K, ciphertext.get(), pk.get(), 1);
      serialized_ciphertext.resize(tbfe_bbg_ciphertext_size(ciphertext.get()));
      tbfe_bbg_ciphertext_serialize(serialized_ciphertext.data(), ciphertext.get());
      end_time = high_resolution_clock::now();
      if (i >= WARMUP) {
        encaps_serialize_time += end_time - start_time;
      }
    }
    std::cout << "tbfe encaps (+ ser):  "
              << duration_cast<microseconds>(encaps_serialize_time / REPEATS).count() << " µs - "
              << beautify_duration(encaps_serialize_time / REPEATS) << std::endl;

    /* benchmark encaps leaf*/
    nanoseconds encaps_leaf_time{0};
    for (unsigned int i = 0; i < (REPEATS + WARMUP); ++i) {
      uint8_t K[SECURITY_PARAMETER];
      auto ciphertext = make_holder<tbfe_bbg_ciphertext_t>(tbfe_bbg_init_ciphertext);

      start_time = high_resolution_clock::now();
      tbfe_bbg_encaps(K, ciphertext.get(), pk_leaf.get(), 10);
      end_time = high_resolution_clock::now();
      if (i >= WARMUP) {
        encaps_leaf_time += end_time - start_time;
      }
    }
    std::cout << "tbfe encaps (leaf):   "
              << duration_cast<microseconds>(encaps_leaf_time / REPEATS).count() << " µs - "
              << beautify_duration(encaps_leaf_time / REPEATS) << std::endl;

    /* benchmark decaps */
    nanoseconds decaps_time{0};
    for (unsigned int i = 0; i < (REPEATS + WARMUP); ++i) {
      uint8_t K[SECURITY_PARAMETER], Kd[SECURITY_PARAMETER];
      auto ciphertext = make_holder<tbfe_bbg_ciphertext_t>(tbfe_bbg_init_ciphertext);

      tbfe_bbg_encaps(K, ciphertext.get(), pk.get(), 1);
      start_time = high_resolution_clock::now();
      tbfe_bbg_decaps(Kd, ciphertext.get(), sk.get(), pk.get());
      end_time = high_resolution_clock::now();
      if (i >= WARMUP) {
        decaps_time += end_time - start_time;
      }
    }
    std::cout << "tbfe decaps:          "
              << duration_cast<microseconds>(decaps_time / REPEATS).count() << " µs - "
              << beautify_duration(decaps_time / REPEATS) << std::endl;

    /* benchmark decaps + serialization */
    nanoseconds decaps_serialize_time{0};
    for (unsigned int i = 0; i < (REPEATS + WARMUP); ++i) {
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
      end_time = high_resolution_clock::now();
      if (i >= WARMUP) {
        decaps_serialize_time += end_time - start_time;
      }
    }
    std::cout << "tbfe decaps (+ ser):  "
              << duration_cast<microseconds>(decaps_serialize_time / REPEATS).count() << " µs - "
              << beautify_duration(decaps_serialize_time / REPEATS) << std::endl;

    /* benchmark decaps leaf */
    nanoseconds decaps_leaf_time{0};
    for (unsigned int i = 0; i < (REPEATS + WARMUP); ++i) {
      uint8_t K[SECURITY_PARAMETER], Kd[SECURITY_PARAMETER];
      auto ciphertext = make_holder<tbfe_bbg_ciphertext_t>(tbfe_bbg_init_ciphertext);

      tbfe_bbg_encaps(K, ciphertext.get(), pk_leaf.get(), 10);
      start_time = high_resolution_clock::now();
      tbfe_bbg_decaps(Kd, ciphertext.get(), sk_leaf.get(), pk_leaf.get());
      end_time = high_resolution_clock::now();
      if (i >= WARMUP) {
        decaps_leaf_time += end_time - start_time;
      }
    }
    std::cout << "tbfe decaps (leaf):   "
              << duration_cast<microseconds>(decaps_leaf_time / REPEATS).count() << " µs - "
              << beautify_duration(decaps_leaf_time / REPEATS) << std::endl;

    /* benchmark puncture ctx */
    nanoseconds punc_time{0};
    for (unsigned int i = 0; i < (REPEATS + WARMUP); ++i) {
      uint8_t K[SECURITY_PARAMETER];
      auto ciphertext = make_holder<tbfe_bbg_ciphertext_t>(tbfe_bbg_init_ciphertext);

      tbfe_bbg_encaps(K, ciphertext.get(), pk.get(), 1);
      start_time = high_resolution_clock::now();
      tbfe_bbg_puncture_ciphertext(sk.get(), ciphertext.get());
      end_time = high_resolution_clock::now();
      if (i >= WARMUP) {
        punc_time += end_time - start_time;
      }
    }
    std::cout << "tbfe punc:            "
              << duration_cast<microseconds>(punc_time / REPEATS).count() << " µs - "
              << beautify_duration(punc_time / REPEATS) << std::endl;

    /* benchmark puncture interval */
    nanoseconds punc_interval_time{0};
    unsigned int time_interval = 1;
    for (unsigned int i = 0; i < (WARMUP + REPEATS); ++i, ++time_interval) {
      start_time = high_resolution_clock::now();
      tbfe_bbg_puncture_interval(sk.get(), pk.get(), time_interval);
      end_time = high_resolution_clock::now();
      if (i >= WARMUP) {
        punc_interval_time += end_time - start_time;
      }
    }
    std::cout << "tbfe punc (interval): "
              << duration_cast<microseconds>(punc_interval_time / REPEATS).count() << " µs - "
              << beautify_duration(punc_interval_time / REPEATS) << std::endl;
  }

  // ### TBFE PERFORMANCE BENCHMARK
  struct bench_data {
    bench_data(std::string_view o, unsigned int i, nanoseconds t, size_t s)
      : operation{o}, interval{i}, time{t}, size{s} {}

    bench_data(std::string_view o, unsigned int i, nanoseconds t)
      : operation{o}, interval{i}, time{t}, size{} {}

    bench_data(std::string_view o, unsigned int i, size_t s)
      : operation{o}, interval{i}, time{}, size{s} {}

    std::string_view operation;
    unsigned int interval;
    nanoseconds time;
    size_t size;

    constexpr bool operator<(const bench_data& rhs) {
      return std::make_tuple(operation, interval) < std::make_tuple(rhs.operation, rhs.interval);
    }
  };

  void write_to_file(std::ofstream& ofs, double false_positive_prob,
                     const std::vector<bench_data>& data) {
    ofs << "operation;interval;time;size\n";
    ofs << "arity;0;0;" << TBFE_ARITY << '\n';
    ofs << "bf_prob;0;0;" << false_positive_prob << '\n';
    for (auto d : data) {
      ofs << d.operation << ';' << d.interval << ';' << d.time.count() << ';' << d.size << '\n';
    }
  }

  void bench_tbfe_performance(unsigned int bloom_filter_size, double false_positive_prob,
                              unsigned int height) {
    std::cout << "Running 'bench_tbfe_performance' ...\n" << std::endl;

    /* n=2^9, depth = 2^10 =>  2 * 2^9 per day for 17 months, correctness error ~ 2^-10 */

    constexpr unsigned int arity = TBFE_ARITY; // Get arity from config.h
    unsigned int total_depth     = height + 2;
    unsigned int num_intervals   = ((pow(arity, height + 1) - 1) / (arity - 1)) - 1;

    // key pair
    auto sk = make_holder<tbfe_bbg_secret_key_t>(tbfe_bbg_init_secret_key, bloom_filter_size,
                                                 false_positive_prob);
    auto pk = make_holder<tbfe_bbg_public_key_t>(tbfe_bbg_init_public_key, total_depth);

    /* benchmark key generation */
    auto start_time = high_resolution_clock::now();
    tbfe_bbg_keygen(pk.get(), sk.get());
    auto keygen_time = high_resolution_clock::now() - start_time;

    /* Print some stats */
    std::cout << "------------------------------------------------" << std::endl;
    std::cout << "|############# ARITY " << arity << " ; HEIGHT " << height << " ##############"
              << std::endl;
    std::cout << "------------------------------------------------" << std::endl;
    std::cout << "|tbfe keygen:          " << duration_cast<microseconds>(keygen_time).count()
              << "| µs - " << beautify_duration(keygen_time) << std::endl;
    std::cout << "|tbfe key parameters:" << std::endl;
    std::cout << "|    hash functions:   " << pk.get()->bloom_filter_hashes << std::endl;
    std::cout << "|    num elements:     " << bloom_filter_size << std::endl;
    std::cout << "|    bloomfilter size: " << pk.get()->bloom_filter_size << std::endl;
    std::cout << "|    correctness err:  " << false_positive_prob << std::endl;

    std::cout << "|tree parameters:      " << std::endl;
    std::cout << "|    arity:            " << arity << std::endl;
    std::cout << "|    height:           " << height << std::endl;
    std::cout << "|    # of intervals:   " << num_intervals << std::endl;
    std::cout << "------------------------------------------------" << std::endl;

    /* start benchmark */
    // Capture average encaps, decaps and puncture time
    nanoseconds encaps_time{0};
    nanoseconds decaps_time{0};
    nanoseconds puncture_time{0};
    // Capture how long the whole benchmark takes
    nanoseconds run_time{0};
    // Buffer for encapsualated key
    std::array<uint8_t, SECURITY_PARAMETER> K;
    // Buffer for decapsulated key
    std::array<uint8_t, SECURITY_PARAMETER> Kd;
    // Decaps failure counter --> check if (K == Kd)
    auto failures = 0;
    // Save min, max and total sum of sk key size
    unsigned int size_sk_min       = UINT_MAX;
    unsigned int size_sk_max       = 0;
    unsigned int size_sk_sum       = 0;
    unsigned int size_sk_max_index = 1;
    unsigned int size_sk_min_index = 1;
    // Record size of sk at every interval
    std::vector<unsigned int> size_sk(num_intervals);
    // Record size of sk_time at every interval
    std::vector<unsigned int> sk_time_size(num_intervals);
    std::vector<bench_data> bench_data;

    std::cout << "|          << RUNNING BENCHMARK >>" << std::endl;
    auto start_time_bench = high_resolution_clock::now();

    // 1.) Get secret key size for interval 1
    auto ciphertext = make_holder<tbfe_bbg_ciphertext_t>(tbfe_bbg_init_ciphertext);
    size_sk[0] = size_sk_min = size_sk_max = size_sk_sum = tbfe_bbg_secret_key_size(sk.get());
    sk_time_size[0]                                      = sk->sk_time->size;

    bench_data.emplace_back("bf_hashes", 0, nanoseconds{0}, pk.get()->bloom_filter_hashes);
    bench_data.emplace_back("bf_size", 0, nanoseconds{0}, pk.get()->bloom_filter_size);
    bench_data.emplace_back("height", 0, nanoseconds{0}, height);
    bench_data.emplace_back("num_elements", 0, nanoseconds{0}, bloom_filter_size);
    bench_data.emplace_back("num_intervals", 0, nanoseconds{0}, num_intervals);

    bench_data.emplace_back("keygen", 0, keygen_time, 0);
    bench_data.emplace_back("sk size", 0, nanoseconds{0}, size_sk[0]);
    bench_data.emplace_back("sk time size", 0, nanoseconds{0}, sk_time_size[0]);

    // 2.) Encaps and Decaps for Interval 1
    start_time    = high_resolution_clock::now();
    auto status   = tbfe_bbg_encaps(K.data(), ciphertext.get(), pk.get(), 1);
    auto end_time = high_resolution_clock::now();
    encaps_time += end_time - start_time;

    bench_data.emplace_back("encaps", 1, end_time - start_time, 0);
    bench_data.emplace_back("ctxt size", 1, nanoseconds{0},
                            tbfe_bbg_ciphertext_size(ciphertext.get()));

    start_time = high_resolution_clock::now();
    status |= tbfe_bbg_decaps(Kd.data(), ciphertext.get(), sk.get(), pk.get());
    end_time = high_resolution_clock::now();
    decaps_time += end_time - start_time;

    bench_data.emplace_back("decaps", 1, end_time - start_time, 0);

    if (K != Kd) {
      ++failures;
    }

    for (unsigned int i = 2; i <= num_intervals; ++i) {
      // 3.) Puncture interval i
      start_time = high_resolution_clock::now();
      status |= tbfe_bbg_puncture_interval(sk.get(), pk.get(), i);
      end_time = high_resolution_clock::now();
      puncture_time += end_time - start_time;

      bench_data.emplace_back("punc", i - 1, end_time - start_time, 0);

      // 4.) Get secret key size of interval i
      size_sk[i - 1] = tbfe_bbg_secret_key_size(sk.get());
      if (size_sk[i - 1] < size_sk_min) {
        size_sk_min       = size_sk[i - 1];
        size_sk_min_index = i;
      }
      if (size_sk[i - 1] > size_sk_max) {
        size_sk_max       = size_sk[i - 1];
        size_sk_max_index = i;
      }
      size_sk_sum += size_sk[i - 1];
      sk_time_size[i - 1] = sk->sk_time->size;

      bench_data.emplace_back("sk size", i, nanoseconds{0}, size_sk[i - 1]);
      bench_data.emplace_back("sk time size", i, nanoseconds{0}, sk_time_size[i - 1]);

      // 5.) Encaps and Decaps for Interval i
      start_time = high_resolution_clock::now();
      status |= tbfe_bbg_encaps(K.data(), ciphertext.get(), pk.get(), i);
      end_time = high_resolution_clock::now();
      encaps_time += end_time - start_time;

      bench_data.emplace_back("encaps", i, end_time - start_time, 0);
      bench_data.emplace_back("ctxt size", i, nanoseconds{0},
                              tbfe_bbg_ciphertext_size(ciphertext.get()));

      start_time = high_resolution_clock::now();
      status |= tbfe_bbg_decaps(Kd.data(), ciphertext.get(), sk.get(), pk.get());
      end_time = high_resolution_clock::now();
      decaps_time += end_time - start_time;

      bench_data.emplace_back("decaps", i, end_time - start_time, 0);

      if (K != Kd) {
        ++failures;
      }
    }
    run_time = high_resolution_clock::now() - start_time_bench;

    // Print some nice output
    std::cout << "------------------------------------------------" << std::endl;
    std::cout << "|size pk:              " << tbfe_bbg_public_key_size(pk.get()) << " bytes"
              << std::endl;
    std::cout << "|size ctx:             " << tbfe_bbg_ciphertext_size(ciphertext.get()) << " bytes"
              << std::endl;
    std::cout << "|size sk (min):        " << size_sk_min
              << " bytes @ index = " << size_sk_min_index << std::endl;
    std::cout << "|size sk (max):        " << size_sk_max
              << " bytes @ index = " << size_sk_max_index << std::endl;
    std::cout << "|size sk (avg):        " << size_sk_sum / num_intervals << " bytes" << std::endl;
    std::cout << "|-----------------------------------------------" << std::endl;
    std::cout << "|status==BFE_SUCCESS?  " << (status == BFE_SUCCESS) << std::endl;
    std::cout << "|failed decaps:        " << failures << std::endl;
    std::cout << "|tbfe encaps (avg):    "
              << duration_cast<microseconds>(encaps_time / num_intervals).count() << " µs - "
              << beautify_duration(encaps_time / num_intervals) << std::endl;
    std::cout << "|tbfe decaps (avg):    "
              << duration_cast<microseconds>(decaps_time / num_intervals).count() << " µs - "
              << beautify_duration(decaps_time / num_intervals) << std::endl;
    std::cout << "|tbfe punc (avg):      "
              << duration_cast<microseconds>(puncture_time / (num_intervals - 1)).count()
              << " µs - " << beautify_duration(puncture_time / (num_intervals - 1)) << std::endl;
    std::cout << "------------------------------------------------" << std::endl;
    std::cout << "|  << BENCHMARK RUNTIME :   " << beautify_duration(run_time) << " >>"
              << std::endl;
    std::cout << "------------------------------------------------" << std::endl;
    std::cout << std::endl;

    // Write key sizes to csv file
    std::ofstream ofs{"tbfe_performance.csv", std::ios::app};
    std::sort(bench_data.begin(), bench_data.end());
    write_to_file(ofs, false_positive_prob, bench_data);
  }
} // namespace

int main(int argc, char** argv) {
  cxxopts::Options options{"bench", "(TB-)BFE benchmarks"};

  /* n=2^19 >= 2^12 per day for 3 months, correctness error ~ 2^-10 */

  options.add_options()("n,num-elements", "Number of elements to store in the Bloom filter",
                        cxxopts::value<unsigned int>()->default_value("524288")) // == 2^19
      ("prob", "False positive probability of the Bloom filter",
       cxxopts::value<double>()->default_value("0.0009765625")) // == 2^-10
      ("height", "Height of the TB-BFE tree", cxxopts::value<unsigned int>()->default_value("10"));
  options.allow_unrecognised_options();

  auto result = options.parse(argc, argv);
  if (result.count("help")) {
    std::cout << options.help() << std::endl;
    return 0;
  }

  const auto unmatched = result.unmatched();
  if (unmatched.size() < 1) {
    bench_bfe(result["num-elements"].as<unsigned int>(), result["prob"].as<double>());
    bench_tbfe(result["num-elements"].as<unsigned int>(), result["prob"].as<double>(),
               result["height"].as<unsigned int>());
    return 0;
  }

  for (const auto& arg : unmatched) {
    if (arg == "bfe") {
      bench_bfe(result["num-elements"].as<unsigned int>(), result["prob"].as<double>());
    } else if (arg == "tbfe") {
      bench_tbfe(result["num-elements"].as<unsigned int>(), result["prob"].as<double>(),
                 result["height"].as<unsigned int>());
    } else if (arg == "tbfe-perf") {
      bench_tbfe_performance(result["num-elements"].as<unsigned int>(), result["prob"].as<double>(),
                             result["height"].as<unsigned int>());
    } else {
      std::cout << "Unknown benchmark: " << arg
                << " - valid benchmarks are 'bfe', 'tbfe' and 'tbfe-perf'." << std::endl;
      return 1;
    }
  }

  return 0;
}
