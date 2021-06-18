#include "vector.h"

#include "utils.h"

#include <errno.h>
#include <stdlib.h>

int vector_init(vector_t* v, size_t capacity) {
  if (!v) {
    return EINVAL;
  }

  if (capacity) {
    v->items = calloc(capacity, sizeof(*v->items));
    if (!v->items) {
      return EINVAL;
    }
  } else {
    v->items = NULL;
  }

  v->capacity = capacity;
  v->size     = 0;

  return 0;
}

vector_t* vector_new(size_t capacity) {
  vector_t* v = malloc(sizeof(*v));
  if (!v) {
    return NULL;
  }

  if (vector_init(v, capacity)) {
    free(v);
    v = NULL;
  }

  return v;
}

size_t vector_size(vector_t* v) {
  if (!v) {
    return 0;
  }
  return v->size;
}

static int vector_reserve(vector_t* v, size_t capacity) {
  if (capacity < v->size) {
    /* do not shrink */
    return 0;
  }

  void** items = realloc(v->items, sizeof(*items) * capacity);
  if (!items) {
    return ENOMEM;
  }

  v->items    = items;
  v->capacity = capacity;

  return 0;
}

int vector_copy(vector_t* c, vector_t* a) {
  if (!c || !a) {
    return EINVAL;
  }

  const size_t a_size = vector_size(a);
  /* nothing to do */
  if (!a_size) {
    return 0;
  }

  int ret = vector_reserve(c, vector_size(c) + a_size);
  if (ret) {
    return ret;
  }

  memcpy(&c->items[c->size], a->items, sizeof(*c->items) * a_size);
  c->size += a_size;

  return 0;
}

int vector_add(vector_t* v, void* item) {
  if (!v) {
    return EINVAL;
  }

  if (v->capacity == v->size) {
    /* double the reserved size */
    const int ret = vector_reserve(v, MAX(v->capacity, 1) * 2);
    if (ret) {
      return ret;
    }
  }
  v->items[v->size++] = item;
  return 0;
}

int vector_set(vector_t* v, size_t index, void* item) {
  if (!v || index >= v->size) {
    return EINVAL;
  }

  v->items[index] = item;
  return 0;
}

void* vector_get(vector_t* v, size_t index) {
  if (!v || index >= v->size) {
    return NULL;
  }

  return v->items[index];
}

int vector_delete(vector_t* v, size_t index) {
  if (!v || index >= v->size) {
    return EINVAL;
  }

  if (index < v->size - 1) {
    memmove(&v->items[index], &v->items[index + 1], sizeof(*v->items) * (v->size - index - 1));
  }
  /* not necessary - just to be on the safe side */
  v->items[--v->size] = NULL;

  /* shrink if capacity is 4 times the size */
  if (v->size > 0 && v->size <= v->capacity / 4) {
    return vector_reserve(v, v->capacity / 2);
  }
  return 0;
}

void vector_clear(vector_t* v) {
  if (v) {
    free(v->items);
    v->items    = NULL;
    v->capacity = 0;
    v->size     = 0;
  }
}

void vector_free(vector_t* v) {
  vector_clear(v);
  free(v);
}
