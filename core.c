/* relic setup */

#include <relic/relic.h>
#include <stdbool.h>

static bool core_init_run = false;
unsigned int order_size;

__attribute__((constructor)) static void init_relic(void) {
  if (!core_get()) {
    core_init();
    core_init_run = true;
  }

  ep_param_set_any_pairf();

  bn_t order;
  bn_new(order);
  ep_curve_get_ord(order);
  order_size = bn_size_bin(order);
  bn_free(order);
}

__attribute__((destructor)) static void clean_relic(void) {
  if (core_init_run) {
    core_init_run = false;
    core_clean();
  }
}

