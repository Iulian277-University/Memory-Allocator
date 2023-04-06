/* SPDX-License-Identifier: BSD-3-Clause */

#pragma once

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include "printf.h"

extern struct block_meta *global_base; /* Head of the linked list */
extern int heap_initialized; /* Flag to check if the heap is initialized */
extern size_t threshold; /* Threshold for `mmap()` when `malloc()`ing or `calloc()`ing */

// Malloc
void *prealloc_heap();

void *sbrk_alloc(size_t size);
void *mmap_alloc(size_t size);

struct block_meta *find_best_free_block(size_t size);
void *split_if_possible(struct block_meta *block, size_t size);
void *alloc_on_free_block(size_t size);
void *expand_last_block(size_t size);

void *os_malloc(size_t size);

// Free
void coalesce_blocks();
void merge_adjacent_free_blocks(struct block_meta *block_ptr);
// struct block_meta *find_block(struct block_meta *block_ptr);
void os_free(void *ptr);

void *os_calloc(size_t nmemb, size_t size);
void *os_realloc(void *ptr, size_t size);
