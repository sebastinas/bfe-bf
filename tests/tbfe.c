#include "../include/tbfe-bbg.h"
#include "../tbfe-bbg-tools.h"
#undef DOUBLE
#undef CALL

#include <cgreen/cgreen.h>

static const unsigned bloom_filter_size = 50;
static const unsigned total_depth       = 4 + 2;
static const double false_positive_prob = 0.001;

Describe(TBFE);
BeforeEach(TBFE) {}
AfterEach(TBFE) {}

Ensure(TBFE, same_key_returned_by_encapsulate_and_decapsulate) {
  tbfe_bbg_secret_key_t secret_key;
  tbfe_bbg_public_key_t public_key;
  tbfe_bbg_ciphertext_t ciphertext;
  uint8_t key[SECURITY_PARAMETER];
  uint8_t decapsulated_key[SECURITY_PARAMETER];

  tbfe_bbg_init_public_key(&public_key, total_depth);
  tbfe_bbg_init_secret_key(&secret_key, bloom_filter_size, false_positive_prob);
  tbfe_bbg_init_ciphertext(&ciphertext);

  assert_that(tbfe_bbg_keygen(&public_key, &secret_key), is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_encaps(key, &ciphertext, &public_key, 1), is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_decaps(decapsulated_key, &ciphertext, &secret_key, &public_key),
              is_equal_to(BFE_SUCCESS));

  assert_that(key, is_equal_to_contents_of(decapsulated_key, SECURITY_PARAMETER));

  tbfe_bbg_clear_public_key(&public_key);
  tbfe_bbg_clear_secret_key(&secret_key);
  tbfe_bbg_clear_ciphertext(&ciphertext);
}

Ensure(TBFE, ciphertext_not_decapsulated_after_interval_puncture) {
  tbfe_bbg_secret_key_t secret_key;
  tbfe_bbg_public_key_t public_key;
  tbfe_bbg_ciphertext_t ciphertext;
  uint8_t key[SECURITY_PARAMETER];
  uint8_t decapsulated_punctured_key[SECURITY_PARAMETER];

  tbfe_bbg_init_public_key(&public_key, total_depth);
  tbfe_bbg_init_secret_key(&secret_key, bloom_filter_size, false_positive_prob);
  tbfe_bbg_init_ciphertext(&ciphertext);

  assert_that(tbfe_bbg_keygen(&public_key, &secret_key), is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_encaps(key, &ciphertext, &public_key, 1), is_equal_to(BFE_SUCCESS));

  assert_that(tbfe_bbg_puncture_interval(&secret_key, &public_key, 2), is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_decaps(decapsulated_punctured_key, &ciphertext, &secret_key, &public_key),
              is_not_equal_to(BFE_SUCCESS));

  tbfe_bbg_clear_public_key(&public_key);
  tbfe_bbg_clear_secret_key(&secret_key);
  tbfe_bbg_clear_ciphertext(&ciphertext);
}

Ensure(TBFE, ciphertext_not_decapsulated_after_ciphertext_puncture) {
  tbfe_bbg_secret_key_t secret_key;
  tbfe_bbg_public_key_t public_key;
  tbfe_bbg_ciphertext_t ciphertext;
  uint8_t key[SECURITY_PARAMETER];
  uint8_t decapsulated_key[SECURITY_PARAMETER];

  tbfe_bbg_init_public_key(&public_key, total_depth);
  tbfe_bbg_init_secret_key(&secret_key, bloom_filter_size, false_positive_prob);
  tbfe_bbg_init_ciphertext(&ciphertext);

  assert_that(tbfe_bbg_keygen(&public_key, &secret_key), is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_encaps(key, &ciphertext, &public_key, 1), is_equal_to(BFE_SUCCESS));

  assert_that(tbfe_bbg_puncture_ciphertext(&secret_key, &ciphertext), is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_decaps(decapsulated_key, &ciphertext, &secret_key, &public_key),
              is_not_equal_to(BFE_SUCCESS));

  tbfe_bbg_clear_public_key(&public_key);
  tbfe_bbg_clear_secret_key(&secret_key);
  tbfe_bbg_clear_ciphertext(&ciphertext);
}

Ensure(TBFE, multiple_ciphertext_punctures) {
  tbfe_bbg_secret_key_t secret_key;
  tbfe_bbg_public_key_t public_key;
  tbfe_bbg_ciphertext_t ciphertext;
  uint8_t key[SECURITY_PARAMETER];
  uint8_t decapsulated_key[SECURITY_PARAMETER];

  unsigned failures = 0;

  tbfe_bbg_init_public_key(&public_key, total_depth);
  tbfe_bbg_init_secret_key(&secret_key, bloom_filter_size, false_positive_prob);

  assert_that(tbfe_bbg_keygen(&public_key, &secret_key), is_equal_to(BFE_SUCCESS));

  for (size_t j = 0; j < bloom_filter_size / (TESTS * 10); j++) {
    tbfe_bbg_init_ciphertext(&ciphertext);

    assert_that(tbfe_bbg_encaps(key, &ciphertext, &public_key, 1), is_equal_to(BFE_SUCCESS));
    int ret = tbfe_bbg_decaps(decapsulated_key, &ciphertext, &secret_key, &public_key);
    assert_that(tbfe_bbg_puncture_ciphertext(&secret_key, &ciphertext), is_equal_to(BFE_SUCCESS));

    if (ret) {
      failures++;
    } else {
      assert_that(key, is_equal_to_contents_of(decapsulated_key, SECURITY_PARAMETER));
    }

    tbfe_bbg_clear_ciphertext(&ciphertext);
  }
  assert_that_double(failures, is_less_than_double(bloom_filter_size / 40));

  tbfe_bbg_clear_public_key(&public_key);
  tbfe_bbg_clear_secret_key(&secret_key);
}

Ensure(TBFE, different_public_key_for_encapsulation_and_decapsulation) {
  tbfe_bbg_secret_key_t secret_key;
  tbfe_bbg_secret_key_t secret_key2;
  tbfe_bbg_public_key_t public_key;
  tbfe_bbg_public_key_t public_key2;
  tbfe_bbg_ciphertext_t ciphertext;
  uint8_t key[SECURITY_PARAMETER];
  uint8_t decapsulated_key[SECURITY_PARAMETER];

  tbfe_bbg_init_public_key(&public_key, total_depth);
  tbfe_bbg_init_public_key(&public_key2, total_depth);
  tbfe_bbg_init_secret_key(&secret_key, bloom_filter_size, false_positive_prob);
  tbfe_bbg_init_secret_key(&secret_key2, bloom_filter_size, false_positive_prob);

  tbfe_bbg_init_ciphertext(&ciphertext);

  assert_that(tbfe_bbg_keygen(&public_key, &secret_key), is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_keygen(&public_key2, &secret_key2), is_equal_to(BFE_SUCCESS));

  assert_that(tbfe_bbg_encaps(key, &ciphertext, &public_key, 1), is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_decaps(decapsulated_key, &ciphertext, &secret_key, &public_key2),
              is_not_equal_to(BFE_SUCCESS));

  tbfe_bbg_clear_public_key(&public_key);
  tbfe_bbg_clear_public_key(&public_key2);
  tbfe_bbg_clear_secret_key(&secret_key);
  tbfe_bbg_clear_secret_key(&secret_key2);
  tbfe_bbg_clear_ciphertext(&ciphertext);
}

Ensure(TBFE, different_secret_key_for_encapsulation_and_decapsulation) {
  tbfe_bbg_secret_key_t secret_key;
  tbfe_bbg_secret_key_t secret_key2;
  tbfe_bbg_public_key_t public_key;
  tbfe_bbg_public_key_t public_key2;
  tbfe_bbg_ciphertext_t ciphertext;
  uint8_t key[SECURITY_PARAMETER];
  uint8_t decapsulated_key[SECURITY_PARAMETER];

  tbfe_bbg_init_public_key(&public_key, total_depth);
  tbfe_bbg_init_public_key(&public_key2, total_depth);
  tbfe_bbg_init_secret_key(&secret_key, bloom_filter_size, false_positive_prob);
  tbfe_bbg_init_secret_key(&secret_key2, bloom_filter_size, false_positive_prob);

  tbfe_bbg_init_ciphertext(&ciphertext);

  assert_that(tbfe_bbg_keygen(&public_key, &secret_key), is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_keygen(&public_key2, &secret_key2), is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_encaps(key, &ciphertext, &public_key, 1), is_equal_to(BFE_SUCCESS));

  assert_that(tbfe_bbg_decaps(decapsulated_key, &ciphertext, &secret_key2, &public_key),
              is_equal_to(BFE_SUCCESS));
  assert_that(key, is_not_equal_to_contents_of(decapsulated_key, SECURITY_PARAMETER));

  tbfe_bbg_clear_public_key(&public_key);
  tbfe_bbg_clear_public_key(&public_key2);
  tbfe_bbg_clear_secret_key(&secret_key);
  tbfe_bbg_clear_secret_key(&secret_key2);
  tbfe_bbg_clear_ciphertext(&ciphertext);
}

Ensure(TBFE, public_key_serialization) {
  tbfe_bbg_secret_key_t secret_key;
  tbfe_bbg_public_key_t public_key;
  tbfe_bbg_public_key_t deserialized_public_key;

  tbfe_bbg_init_public_key(&public_key, total_depth);
  tbfe_bbg_init_secret_key(&secret_key, bloom_filter_size, false_positive_prob);

  assert_that(tbfe_bbg_keygen(&public_key, &secret_key), is_equal_to(BFE_SUCCESS));

  uint8_t* serialized_public_key = malloc(tbfe_bbg_public_key_size(&public_key));
  tbfe_bbg_public_key_serialize(serialized_public_key, &public_key);
  assert_that(tbfe_bbg_public_key_deserialize(&deserialized_public_key, serialized_public_key),
              is_equal_to(BFE_SUCCESS));
  assert_true(tbfe_bbg_public_keys_are_equal(&public_key, &deserialized_public_key));

  tbfe_bbg_clear_public_key(&public_key);
  tbfe_bbg_clear_secret_key(&secret_key);
  tbfe_bbg_clear_public_key(&deserialized_public_key);
  free(serialized_public_key);
}

Ensure(TBFE, encapsulation_with_deserialized_public_key) {
  tbfe_bbg_secret_key_t secret_key;
  tbfe_bbg_public_key_t public_key;
  tbfe_bbg_public_key_t deserialized_public_key;
  tbfe_bbg_ciphertext_t ciphertext;
  uint8_t key[SECURITY_PARAMETER];
  uint8_t decapsulated_key[SECURITY_PARAMETER];

  tbfe_bbg_init_public_key(&public_key, total_depth);
  tbfe_bbg_init_secret_key(&secret_key, bloom_filter_size, false_positive_prob);
  tbfe_bbg_init_ciphertext(&ciphertext);

  assert_that(tbfe_bbg_keygen(&public_key, &secret_key), is_equal_to(BFE_SUCCESS));

  uint8_t* serialized_public_key = malloc(tbfe_bbg_public_key_size(&public_key));
  tbfe_bbg_public_key_serialize(serialized_public_key, &public_key);
  assert_that(tbfe_bbg_public_key_deserialize(&deserialized_public_key, serialized_public_key),
              is_equal_to(BFE_SUCCESS));
  assert_true(tbfe_bbg_public_keys_are_equal(&public_key, &deserialized_public_key));

  assert_that(tbfe_bbg_encaps(key, &ciphertext, &public_key, 1), is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_decaps(decapsulated_key, &ciphertext, &secret_key, &deserialized_public_key),
              is_equal_to(BFE_SUCCESS));
  assert_that(key, is_equal_to_contents_of(decapsulated_key, SECURITY_PARAMETER));

  tbfe_bbg_clear_public_key(&public_key);
  tbfe_bbg_clear_public_key(&deserialized_public_key);
  tbfe_bbg_clear_secret_key(&secret_key);
  tbfe_bbg_clear_ciphertext(&ciphertext);
  free(serialized_public_key);
}

Ensure(TBFE, secret_key_serialization) {
  tbfe_bbg_secret_key_t secret_key;
  tbfe_bbg_public_key_t public_key;
  tbfe_bbg_ciphertext_t ciphertext;
  uint8_t key[SECURITY_PARAMETER];
  uint8_t decapsulated_key[SECURITY_PARAMETER];
  uint8_t decapsulated_punctured_key[SECURITY_PARAMETER];
  tbfe_bbg_secret_key_t deserialized_secret_key;
  tbfe_bbg_secret_key_t deserialized_punctured_secret_key;

  tbfe_bbg_init_public_key(&public_key, total_depth);
  tbfe_bbg_init_secret_key(&secret_key, bloom_filter_size, false_positive_prob);
  tbfe_bbg_init_ciphertext(&ciphertext);

  assert_that(tbfe_bbg_keygen(&public_key, &secret_key), is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_encaps(key, &ciphertext, &public_key, 1), is_equal_to(BFE_SUCCESS));

  uint8_t* serialized_secret_key = malloc(tbfe_bbg_secret_key_size(&secret_key));
  tbfe_bbg_secret_key_serialize(serialized_secret_key, &secret_key);

  assert_that(tbfe_bbg_secret_key_deserialize(&deserialized_secret_key, serialized_secret_key),
              is_equal_to(BFE_SUCCESS));
  assert_true(tbfe_bbg_secret_keys_are_equal(&secret_key, &deserialized_secret_key));

  assert_that(tbfe_bbg_decaps(decapsulated_key, &ciphertext, &deserialized_secret_key, &public_key),
              is_equal_to(BFE_SUCCESS));
  assert_that(key, is_equal_to_contents_of(decapsulated_key, SECURITY_PARAMETER));

  assert_that(tbfe_bbg_puncture_ciphertext(&secret_key, &ciphertext), is_equal_to(BFE_SUCCESS));
  uint8_t* serialized_punctured_secret_key = malloc(tbfe_bbg_secret_key_size(&secret_key));
  tbfe_bbg_secret_key_serialize(serialized_punctured_secret_key, &secret_key);

  assert_that(tbfe_bbg_secret_key_deserialize(&deserialized_punctured_secret_key,
                                              serialized_punctured_secret_key),
              is_equal_to(BFE_SUCCESS));
  assert_true(tbfe_bbg_secret_keys_are_equal(&secret_key, &deserialized_punctured_secret_key));

  assert_that(tbfe_bbg_decaps(decapsulated_punctured_key, &ciphertext,
                              &deserialized_punctured_secret_key, &public_key),
              is_not_equal_to(BFE_SUCCESS));

  tbfe_bbg_clear_public_key(&public_key);
  tbfe_bbg_clear_secret_key(&secret_key);
  tbfe_bbg_clear_ciphertext(&ciphertext);
  tbfe_bbg_clear_secret_key(&deserialized_secret_key);
  tbfe_bbg_clear_secret_key(&deserialized_punctured_secret_key);
  free(serialized_secret_key);
  free(serialized_punctured_secret_key);
}

Ensure(TBFE, ciphertext_serialization) {
  tbfe_bbg_secret_key_t secret_key;
  tbfe_bbg_public_key_t public_key;
  tbfe_bbg_ciphertext_t ciphertext;
  tbfe_bbg_ciphertext_t deserialized_ciphertext;
  uint8_t key[SECURITY_PARAMETER];

  tbfe_bbg_init_public_key(&public_key, total_depth);
  tbfe_bbg_init_secret_key(&secret_key, bloom_filter_size, false_positive_prob);
  tbfe_bbg_init_ciphertext(&ciphertext);

  assert_that(tbfe_bbg_keygen(&public_key, &secret_key), is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_encaps(key, &ciphertext, &public_key, 1), is_equal_to(BFE_SUCCESS));

  uint8_t* serialized_ciphertext = malloc(tbfe_bbg_ciphertext_size(&ciphertext));
  tbfe_bbg_ciphertext_serialize(serialized_ciphertext, &ciphertext);
  assert_that(tbfe_bbg_ciphertext_deserialize(&deserialized_ciphertext, serialized_ciphertext),
              is_equal_to(BFE_SUCCESS));
  assert_true(tbfe_bbg_ciphertexts_are_equal(&ciphertext, &deserialized_ciphertext));

  tbfe_bbg_clear_public_key(&public_key);
  tbfe_bbg_clear_secret_key(&secret_key);
  tbfe_bbg_clear_ciphertext(&ciphertext);
  tbfe_bbg_clear_ciphertext(&deserialized_ciphertext);
  free(serialized_ciphertext);
}

Ensure(TBFE, same_key_returned_by_encapsulate_and_decapsulate_with_serialization) {
  tbfe_bbg_secret_key_t secret_key;
  tbfe_bbg_public_key_t public_key;
  tbfe_bbg_public_key_t deserialized_public_key;
  tbfe_bbg_ciphertext_t ciphertext;
  tbfe_bbg_ciphertext_t deserialized_ciphertext;
  uint8_t key[SECURITY_PARAMETER];
  uint8_t decapsulated_key[SECURITY_PARAMETER];

  tbfe_bbg_init_public_key(&public_key, total_depth);
  tbfe_bbg_init_secret_key(&secret_key, bloom_filter_size, false_positive_prob);
  tbfe_bbg_init_ciphertext(&ciphertext);

  assert_that(tbfe_bbg_keygen(&public_key, &secret_key), is_equal_to(BFE_SUCCESS));

  uint8_t* serialized_public_key = malloc(tbfe_bbg_public_key_size(&public_key));
  tbfe_bbg_public_key_serialize(serialized_public_key, &public_key);
  assert_that(tbfe_bbg_public_key_deserialize(&deserialized_public_key, serialized_public_key),
              is_equal_to(BFE_SUCCESS));

  assert_that(tbfe_bbg_encaps(key, &ciphertext, &public_key, 1), is_equal_to(BFE_SUCCESS));
  uint8_t* serialized_ciphertext = malloc(tbfe_bbg_ciphertext_size(&ciphertext));
  tbfe_bbg_ciphertext_serialize(serialized_ciphertext, &ciphertext);
  assert_that(tbfe_bbg_ciphertext_deserialize(&deserialized_ciphertext, serialized_ciphertext),
              is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_decaps(decapsulated_key, &deserialized_ciphertext, &secret_key,
                              &deserialized_public_key),
              is_equal_to(BFE_SUCCESS));
  assert_that(key, is_equal_to_contents_of(decapsulated_key, SECURITY_PARAMETER));

  tbfe_bbg_clear_public_key(&public_key);
  tbfe_bbg_clear_public_key(&deserialized_public_key);
  tbfe_bbg_clear_secret_key(&secret_key);
  tbfe_bbg_clear_ciphertext(&ciphertext);
  tbfe_bbg_clear_ciphertext(&deserialized_ciphertext);
  free(serialized_ciphertext);
  free(serialized_public_key);
}

Ensure(TBFE, interval_puncture_same_key_returned_by_encapsulate_and_decapsulate) {
  tbfe_bbg_secret_key_t secret_key;
  tbfe_bbg_public_key_t public_key;
  tbfe_bbg_ciphertext_t ciphertext;
  uint8_t punctured_key[SECURITY_PARAMETER];
  uint8_t decapsulated_punctured_key[SECURITY_PARAMETER];

  tbfe_bbg_init_public_key(&public_key, total_depth);
  tbfe_bbg_init_secret_key(&secret_key, bloom_filter_size, false_positive_prob);
  tbfe_bbg_init_ciphertext(&ciphertext);

  assert_that(tbfe_bbg_keygen(&public_key, &secret_key), is_equal_to(BFE_SUCCESS));

  assert_that(tbfe_bbg_puncture_interval(&secret_key, &public_key, 2), is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_puncture_interval(&secret_key, &public_key, 3), is_equal_to(BFE_SUCCESS));

  assert_that(tbfe_bbg_encaps(punctured_key, &ciphertext, &public_key, 3),
              is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_decaps(decapsulated_punctured_key, &ciphertext, &secret_key, &public_key),
              is_equal_to(BFE_SUCCESS));

  assert_that(punctured_key,
              is_equal_to_contents_of(decapsulated_punctured_key, SECURITY_PARAMETER));

  tbfe_bbg_clear_public_key(&public_key);
  tbfe_bbg_clear_secret_key(&secret_key);
  tbfe_bbg_clear_ciphertext(&ciphertext);
}

Ensure(TBFE, interval_puncture_after_encapsulate_and_decapsulate) {
  tbfe_bbg_secret_key_t secret_key;
  tbfe_bbg_public_key_t public_key;
  tbfe_bbg_ciphertext_t ciphertext;
  uint8_t key[SECURITY_PARAMETER];
  uint8_t decapsulated_key[SECURITY_PARAMETER];

  tbfe_bbg_init_public_key(&public_key, total_depth);
  tbfe_bbg_init_secret_key(&secret_key, bloom_filter_size, false_positive_prob);
  tbfe_bbg_init_ciphertext(&ciphertext);

  assert_that(tbfe_bbg_keygen(&public_key, &secret_key), is_equal_to(BFE_SUCCESS));

  assert_that(tbfe_bbg_encaps(key, &ciphertext, &public_key, 1), is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_decaps(decapsulated_key, &ciphertext, &secret_key, &public_key),
              is_equal_to(BFE_SUCCESS));
  assert_that(key, is_equal_to_contents_of(decapsulated_key, SECURITY_PARAMETER));

  assert_that(tbfe_bbg_puncture_interval(&secret_key, &public_key, 2), is_equal_to(BFE_SUCCESS));

  assert_that(tbfe_bbg_encaps(key, &ciphertext, &public_key, 2), is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_decaps(decapsulated_key, &ciphertext, &secret_key, &public_key),
              is_equal_to(BFE_SUCCESS));
  assert_that(key, is_equal_to_contents_of(decapsulated_key, SECURITY_PARAMETER));

  tbfe_bbg_clear_public_key(&public_key);
  tbfe_bbg_clear_secret_key(&secret_key);
  tbfe_bbg_clear_ciphertext(&ciphertext);
}

Ensure(TBFE, same_key_returned_by_multiple_encapsulate_and_decapsulate) {
  tbfe_bbg_secret_key_t secret_key;
  tbfe_bbg_public_key_t public_key;
  tbfe_bbg_ciphertext_t ciphertext;
  uint8_t key[SECURITY_PARAMETER];
  uint8_t decapsulated_key[SECURITY_PARAMETER];

  tbfe_bbg_init_public_key(&public_key, total_depth);
  tbfe_bbg_init_secret_key(&secret_key, bloom_filter_size, false_positive_prob);
  tbfe_bbg_init_ciphertext(&ciphertext);

  assert_that(tbfe_bbg_keygen(&public_key, &secret_key), is_equal_to(BFE_SUCCESS));

  for (size_t i = 0; i < 10; i++) {
    assert_that(tbfe_bbg_encaps(key, &ciphertext, &public_key, 1), is_equal_to(BFE_SUCCESS));
    assert_that(tbfe_bbg_decaps(decapsulated_key, &ciphertext, &secret_key, &public_key),
                is_equal_to(BFE_SUCCESS));
    assert_that(key, is_equal_to_contents_of(decapsulated_key, SECURITY_PARAMETER));
  }

  tbfe_bbg_clear_public_key(&public_key);
  tbfe_bbg_clear_secret_key(&secret_key);
  tbfe_bbg_clear_ciphertext(&ciphertext);
}

Ensure(TBFE, same_key_returned_by_multiple_encapsulate_and_decapsulate_with_ciphertext_puncture) {
  tbfe_bbg_secret_key_t secret_key;
  tbfe_bbg_public_key_t public_key;
  tbfe_bbg_ciphertext_t ciphertext;
  uint8_t key[SECURITY_PARAMETER];
  uint8_t decapsulated_key[SECURITY_PARAMETER];

  tbfe_bbg_init_public_key(&public_key, total_depth);
  tbfe_bbg_init_secret_key(&secret_key, bloom_filter_size, false_positive_prob);
  tbfe_bbg_init_ciphertext(&ciphertext);

  assert_that(tbfe_bbg_keygen(&public_key, &secret_key), is_equal_to(BFE_SUCCESS));

  for (size_t i = 0; i < 10; i++) {
    assert_that(tbfe_bbg_encaps(key, &ciphertext, &public_key, 1), is_equal_to(BFE_SUCCESS));
    assert_that(tbfe_bbg_decaps(decapsulated_key, &ciphertext, &secret_key, &public_key),
                is_equal_to(BFE_SUCCESS));
    assert_that(key, is_equal_to_contents_of(decapsulated_key, SECURITY_PARAMETER));
    assert_that(tbfe_bbg_puncture_ciphertext(&secret_key, &ciphertext), is_equal_to(BFE_SUCCESS));
  }

  tbfe_bbg_clear_public_key(&public_key);
  tbfe_bbg_clear_secret_key(&secret_key);
  tbfe_bbg_clear_ciphertext(&ciphertext);
}

Ensure(TBFE, puncture_interval_same_key_returned_by_multiple_encapsulate_and_decapsulate) {
  tbfe_bbg_secret_key_t secret_key;
  tbfe_bbg_public_key_t public_key;
  tbfe_bbg_ciphertext_t ciphertext;
  uint8_t key[SECURITY_PARAMETER];
  uint8_t decapsulated_key[SECURITY_PARAMETER];

  tbfe_bbg_init_public_key(&public_key, total_depth);
  tbfe_bbg_init_secret_key(&secret_key, bloom_filter_size, false_positive_prob);
  tbfe_bbg_init_ciphertext(&ciphertext);

  assert_that(tbfe_bbg_keygen(&public_key, &secret_key), is_equal_to(BFE_SUCCESS));

  for (size_t i = 0; i < 10; i++) {
    assert_that(tbfe_bbg_encaps(key, &ciphertext, &public_key, 1), is_equal_to(BFE_SUCCESS));
    assert_that(tbfe_bbg_decaps(decapsulated_key, &ciphertext, &secret_key, &public_key),
                is_equal_to(BFE_SUCCESS));
    assert_that(key, is_equal_to_contents_of(decapsulated_key, SECURITY_PARAMETER));
  }

  assert_that(tbfe_bbg_puncture_interval(&secret_key, &public_key, 2), is_equal_to(BFE_SUCCESS));

  for (size_t i = 0; i < 10; i++) {
    assert_that(tbfe_bbg_encaps(key, &ciphertext, &public_key, 2), is_equal_to(BFE_SUCCESS));
    assert_that(tbfe_bbg_decaps(decapsulated_key, &ciphertext, &secret_key, &public_key),
                is_equal_to(BFE_SUCCESS));
    assert_that(key, is_equal_to_contents_of(decapsulated_key, SECURITY_PARAMETER));
  }

  tbfe_bbg_clear_public_key(&public_key);
  tbfe_bbg_clear_secret_key(&secret_key);
  tbfe_bbg_clear_ciphertext(&ciphertext);
}

Ensure(TBFE, secret_key_serialization_at_leaf) {
  tbfe_bbg_secret_key_t secret_key;
  tbfe_bbg_public_key_t public_key;
  tbfe_bbg_ciphertext_t ciphertext;
  uint8_t key[SECURITY_PARAMETER];
  uint8_t decapsulated_key[SECURITY_PARAMETER];
  uint8_t decapsulated_punctured_key[SECURITY_PARAMETER];
  tbfe_bbg_secret_key_t deserialized_secret_key;
  tbfe_bbg_secret_key_t deserialized_punctured_secret_key;

  tbfe_bbg_init_public_key(&public_key, 5);
  tbfe_bbg_init_secret_key(&secret_key, bloom_filter_size, false_positive_prob);
  tbfe_bbg_init_ciphertext(&ciphertext);

  assert_that(tbfe_bbg_keygen(&public_key, &secret_key), is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_puncture_interval(&secret_key, &public_key, 2), is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_puncture_interval(&secret_key, &public_key, 3), is_equal_to(BFE_SUCCESS));

  assert_that(tbfe_bbg_encaps(key, &ciphertext, &public_key, 3), is_equal_to(BFE_SUCCESS));

  uint8_t* serialized_secret_key = malloc(tbfe_bbg_secret_key_size(&secret_key));
  tbfe_bbg_secret_key_serialize(serialized_secret_key, &secret_key);

  assert_that(tbfe_bbg_secret_key_deserialize(&deserialized_secret_key, serialized_secret_key),
              is_equal_to(BFE_SUCCESS));

  assert_true(tbfe_bbg_secret_keys_are_equal(&secret_key, &deserialized_secret_key));

  assert_that(tbfe_bbg_decaps(decapsulated_key, &ciphertext, &deserialized_secret_key, &public_key),
              is_equal_to(BFE_SUCCESS));
  assert_that(key, is_equal_to_contents_of(decapsulated_key, SECURITY_PARAMETER));

  assert_that(tbfe_bbg_puncture_ciphertext(&secret_key, &ciphertext), is_equal_to(BFE_SUCCESS));
  uint8_t* serialized_punctured_secret_key = malloc(tbfe_bbg_secret_key_size(&secret_key));
  tbfe_bbg_secret_key_serialize(serialized_punctured_secret_key, &secret_key);

  assert_that(tbfe_bbg_secret_key_deserialize(&deserialized_punctured_secret_key,
                                              serialized_punctured_secret_key),
              is_equal_to(BFE_SUCCESS));
  assert_true(tbfe_bbg_secret_keys_are_equal(&secret_key, &deserialized_punctured_secret_key));

  assert_that(tbfe_bbg_decaps(decapsulated_punctured_key, &ciphertext,
                              &deserialized_punctured_secret_key, &public_key),
              is_not_equal_to(BFE_SUCCESS));

  tbfe_bbg_clear_public_key(&public_key);
  tbfe_bbg_clear_secret_key(&secret_key);
  tbfe_bbg_clear_ciphertext(&ciphertext);
  tbfe_bbg_clear_secret_key(&deserialized_secret_key);
  tbfe_bbg_clear_secret_key(&deserialized_punctured_secret_key);
  free(serialized_secret_key);
  free(serialized_punctured_secret_key);
}

Ensure(TBFE, secret_key_serialization_before_puncturing) {
  tbfe_bbg_secret_key_t secret_key;
  tbfe_bbg_public_key_t public_key;
  tbfe_bbg_ciphertext_t ciphertext;
  uint8_t key[SECURITY_PARAMETER];
  uint8_t decapsulated_key[SECURITY_PARAMETER];
  uint8_t decapsulated_punctured_key[SECURITY_PARAMETER];
  tbfe_bbg_secret_key_t deserialized_secret_key;
  tbfe_bbg_secret_key_t deserialized_punctured_secret_key;

  tbfe_bbg_init_public_key(&public_key, 5);
  tbfe_bbg_init_secret_key(&secret_key, bloom_filter_size, false_positive_prob);
  tbfe_bbg_init_ciphertext(&ciphertext);

  assert_that(tbfe_bbg_keygen(&public_key, &secret_key), is_equal_to(BFE_SUCCESS));

  uint8_t* serialized_secret_key = malloc(tbfe_bbg_secret_key_size(&secret_key));
  tbfe_bbg_secret_key_serialize(serialized_secret_key, &secret_key);

  assert_that(tbfe_bbg_secret_key_deserialize(&deserialized_secret_key, serialized_secret_key),
              is_equal_to(BFE_SUCCESS));

  assert_true(tbfe_bbg_secret_keys_are_equal(&secret_key, &deserialized_secret_key));

  assert_that(tbfe_bbg_puncture_interval(&deserialized_secret_key, &public_key, 2),
              is_equal_to(BFE_SUCCESS));
  assert_that(tbfe_bbg_puncture_interval(&deserialized_secret_key, &public_key, 3),
              is_equal_to(BFE_SUCCESS));

  assert_that(tbfe_bbg_encaps(key, &ciphertext, &public_key, 3), is_equal_to(BFE_SUCCESS));

  assert_that(tbfe_bbg_decaps(decapsulated_key, &ciphertext, &deserialized_secret_key, &public_key),
              is_equal_to(BFE_SUCCESS));
  assert_that(key, is_equal_to_contents_of(decapsulated_key, SECURITY_PARAMETER));

  assert_that(tbfe_bbg_puncture_ciphertext(&secret_key, &ciphertext), is_equal_to(BFE_SUCCESS));
  uint8_t* serialized_punctured_secret_key = malloc(tbfe_bbg_secret_key_size(&secret_key));
  tbfe_bbg_secret_key_serialize(serialized_punctured_secret_key, &secret_key);

  assert_that(tbfe_bbg_secret_key_deserialize(&deserialized_punctured_secret_key,
                                              serialized_punctured_secret_key),
              is_equal_to(BFE_SUCCESS));
  assert_true(tbfe_bbg_secret_keys_are_equal(&secret_key, &deserialized_punctured_secret_key));

  assert_that(tbfe_bbg_decaps(decapsulated_punctured_key, &ciphertext,
                              &deserialized_punctured_secret_key, &public_key),
              is_not_equal_to(BFE_SUCCESS));

  tbfe_bbg_clear_public_key(&public_key);
  tbfe_bbg_clear_secret_key(&secret_key);
  tbfe_bbg_clear_ciphertext(&ciphertext);
  tbfe_bbg_clear_secret_key(&deserialized_secret_key);
  tbfe_bbg_clear_secret_key(&deserialized_punctured_secret_key);
  free(serialized_secret_key);
  free(serialized_punctured_secret_key);
}

int main(void) {
  TestSuite* suite = create_test_suite();
  add_test_with_context(suite, TBFE, same_key_returned_by_encapsulate_and_decapsulate);
  add_test_with_context(suite, TBFE, ciphertext_not_decapsulated_after_interval_puncture);
  add_test_with_context(suite, TBFE, ciphertext_not_decapsulated_after_ciphertext_puncture);
  add_test_with_context(suite, TBFE, multiple_ciphertext_punctures);
  add_test_with_context(suite, TBFE, different_public_key_for_encapsulation_and_decapsulation);
  add_test_with_context(suite, TBFE, different_secret_key_for_encapsulation_and_decapsulation);
  add_test_with_context(suite, TBFE, public_key_serialization);
  add_test_with_context(suite, TBFE, encapsulation_with_deserialized_public_key);
  add_test_with_context(suite, TBFE, secret_key_serialization);
  add_test_with_context(suite, TBFE, ciphertext_serialization);
  add_test_with_context(suite, TBFE,
                        same_key_returned_by_encapsulate_and_decapsulate_with_serialization);
  add_test_with_context(suite, TBFE,
                        interval_puncture_same_key_returned_by_encapsulate_and_decapsulate);
  add_test_with_context(suite, TBFE, interval_puncture_after_encapsulate_and_decapsulate);
  add_test_with_context(suite, TBFE, same_key_returned_by_multiple_encapsulate_and_decapsulate);
  add_test_with_context(
      suite, TBFE,
      same_key_returned_by_multiple_encapsulate_and_decapsulate_with_ciphertext_puncture);
  add_test_with_context(
      suite, TBFE, puncture_interval_same_key_returned_by_multiple_encapsulate_and_decapsulate);
  add_test_with_context(suite, TBFE, secret_key_serialization_at_leaf);
  add_test_with_context(suite, TBFE, secret_key_serialization_before_puncturing);
  return run_test_suite(suite, create_text_reporter());
}
