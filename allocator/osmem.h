/* SPDX-License-Identifier: BSD-3-Clause */

#pragma once

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include "printf.h"


void *sbrk_alloc(size_t size);
void *mmap_alloc(size_t size);

struct block_meta *find_free_block(size_t size);
void *alloc_on_free_block(size_t size);

struct block_meta *request_space(struct block_meta *last, size_t size);
void *prealloc_heap();

void *os_malloc(size_t size);
void os_free(void *ptr);
void *os_calloc(size_t nmemb, size_t size);
void *os_realloc(void *ptr, size_t size);
