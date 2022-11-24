/* relic setup */

#include "core.h"
#include "include/types.h"

#include <sodium.h>
#include <stdbool.h>

static bool core_init_run = false;
static bn_t order;
static bn_t one;

unsigned int order_size;

__attribute__((constructor)) static void init_relic(void) {
  if (sodium_init() == -1) {
    // TODO: handle!
  }

  if (!core_get()) {
    core_init();
    core_init_run = true;
  }

  ep_param_set_any_pairf();

  bn_null(order);
  bn_null(one);
  bn_new(order);
  bn_new(one);
  ep_curve_get_ord(order);
  order_size = bn_size_bin(order);
}

__attribute__((destructor)) static void clean_relic(void) {
  if (core_init_run) {
    bn_free(new);
    bn_free(order);

    core_init_run = false;
    core_clean();
  }
}

static bool bn_is_one(const bn_t a) {
  return bn_cmp(a, one) == RLC_EQ;
}

void zp_rand(bn_t b) {
  bn_rand_mod(b, order);
}

void zp_add(bn_t c, const bn_t a, const bn_t b) {
  bn_add(c, a, b);
  bn_mod(c, c, order);
}

void zp_sub(bn_t c, const bn_t a, const bn_t b) {
  bn_sub(c, a, b);
  bn_mod(c, c, order);
  if (bn_sign(c) == RLC_NEG) {
    bn_add(c, c, order);
  }
}

void zp_mul(bn_t c, const bn_t a, const bn_t b) {
  bn_mul(c, a, b);
  if (bn_sign(c) == RLC_NEG) {
    bn_add(c, c, order);
  } else {
    bn_mod(c, c, order);
  }
}

void zp_div(bn_t c, const bn_t a, const bn_t b) {
  bn_t s;
  bn_null(s);

  RLC_TRY {
    bn_new(s);

    bn_gcd_ext(s, c, NULL, b, order);
    if (bn_sign(c) == RLC_NEG) {
      bn_add(c, c, order);
    }

    if (!bn_is_one(a)) {
      bn_new(s);
      bn_mul(s, a, c);
      bn_div_rem(s, c, s, order);
    }
  }
  RLC_FINALLY {
    bn_free(s);
  }
}

void hash_squeeze_zp(bn_t bn, Keccak_HashInstance* ctx) {
  uint8_t buffer[MAX_ORDER_SIZE];
  Keccak_HashSqueeze(ctx, buffer, order_size * 8);
  bn_read_bin(bn, buffer, order_size);
  if (bn_cmp(bn, order) == RLC_GT) {
    bn_mod(bn, bn, order);
  }
}
