// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "helpers.h"

#include <stdbool.h> /* for bool */
#include <unistd.h> /* for sbrk() */
#include <sys/mman.h> /* for mmap() */


static struct block_meta *global_base = NULL;
static bool heap_initialized = false;

void *sbrk_alloc(size_t size)
{
	// Allocate memory on the heap using `sbrk()`
	size_t total_size = METADATA_SIZE + size;
	total_size = ALIGN(total_size);
	struct block_meta *block = (struct block_meta *) sbrk(total_size);
	if (block == (void *) -1)
		return NULL;

	// Initialize the block metadata
	block->size = size;
	block->status = STATUS_ALLOC;
	block->next = global_base;
	global_base = block;

	return (void *)(block + 1);
}

void *mmap_alloc(size_t size)
{
	size_t total_size = METADATA_SIZE + size;
	total_size = ALIGN(total_size);
	struct block_meta *block = (struct block_meta *) mmap(NULL, total_size,
											PROT_READ | PROT_WRITE,
											MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (block == MAP_FAILED)
		return NULL;

	block->size = size;
	block->status = STATUS_MAPPED;
	block->next = NULL;
	return (void *)(block + 1);
}

struct block_meta *find_free_block(size_t size)
{
	struct block_meta *current = global_base;
	size_t total_size = METADATA_SIZE + size;
	while (current != NULL) {
		if (current->status == STATUS_FREE && current->size >= total_size) {
			// Found a free block that can hold the requested size
			return current;
		}
		current = current->next;
	}

	return current;
}

void *alloc_on_free_block(size_t size)
{
	if (global_base != NULL) {
		struct block_meta *block = find_free_block(size);
		if (block != NULL) {
			block->status = STATUS_ALLOC;
			return (void *)(block + 1);
		}
	}

	return NULL;
}

void *prealloc_heap()
{
	// Initialize the heap for the first time
	size_t total_size = PREALLOC_SIZE;
	total_size = ALIGN(total_size);
	struct block_meta *block = (struct block_meta *) sbrk(total_size);
	if (block == (void *) -1)
		return NULL;
	
	block->size = PREALLOC_SIZE;
	block->status = STATUS_FREE;
	block->next = NULL;
	global_base = block;
	heap_initialized = true;
	return (void *)(block + 1);
}

// `sbrk()` with NULL on first request
struct block_meta *request_space(struct block_meta *last, size_t size)
{
	struct block_meta *block;
	size_t total_size = METADATA_SIZE + size;
	total_size = ALIGN(total_size);
	block = (struct block_meta *) sbrk(total_size);
	if (block == (void *) -1)
		return NULL;

	if (last) { // NULL on first request
		last->next = block;
	}

	block->size = size;
	block->status = STATUS_ALLOC;
	block->next = NULL;
	return block;
}

void *os_malloc(size_t size)
{
	struct block_meta *block;
	void *res = NULL;
	size_t total_size;

	if (size <= 0)
		return NULL;

	size = ALIGN(size);

	/* Alloc with `sbrk()` or `mmap()` depending on the allocated `size` */
    if (size < MMAP_THRESHOLD) {
		/* Initialize the heap for the first time */
		if (!heap_initialized)
			res = prealloc_heap();
		res = alloc_on_free_block(size);
		return res ? res : sbrk_alloc(size);
	}
	else {
		res = alloc_on_free_block(size);
		return res ? res : mmap_alloc(size);
	}

	return res;
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;

	/* Find the metadata block for the given ptr */
	struct block_meta *block_ptr = (struct block_meta *) ptr - 1;

	/* Check if the block is valid */
	if (block_ptr->status == STATUS_MAPPED) {
		/* The block was allocated using mmap() */
		if (munmap(block_ptr, block_ptr->size + METADATA_SIZE) == -1) {
			/* munmap() failed */
			return;
		}
	} 
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	return NULL;
}
