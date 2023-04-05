/* SPDX-License-Identifier: BSD-3-Clause */

#pragma once

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include "printf.h"

// Malloc
void *prealloc_heap();

void *sbrk_alloc(size_t size);
void *mmap_alloc(size_t size);

struct block_meta *find_free_block(size_t size);
void *alloc_on_free_block(size_t size);

void *os_malloc(size_t size);

// Free
void merge_adjacent_block(struct block_meta *block_ptr);
void os_free(void *ptr);

void *os_calloc(size_t nmemb, size_t size);
void *os_realloc(void *ptr, size_t size);
