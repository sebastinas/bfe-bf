#ifndef VECTOR_H
#define VECTOR_H

#include "include/types.h"

#include <stddef.h>

struct vector {
  void** items;
  size_t capacity;
  size_t size;
};

vector_t* vector_new(size_t capacity);
int vector_init(vector_t* v, size_t capacity);
size_t vector_size(vector_t* v);
int vector_copy(vector_t* c, vector_t* a);
int vector_add(vector_t* v, void* item);
int vector_set(vector_t* v, size_t index, void* item);
void* vector_get(vector_t* v, size_t index);
int vector_delete(vector_t* v, size_t index);
void vector_clear(vector_t* v);
void vector_free(vector_t* v);

#endif
