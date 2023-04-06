// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "helpers.h"

#include <stdbool.h> /* for bool */
#include <unistd.h> /* for sbrk() */
#include <sys/mman.h> /* for mmap() */

struct block_meta *global_base = NULL; /* Head of the linked list */
int heap_initialized = 0; /* Flag to check if the heap is initialized */
size_t threshold = MMAP_THRESHOLD; /* Threshold for `mmap()` when `malloc()`ing or `calloc()`ing */

void *sbrk_alloc(size_t size)
{
	/* Allocate memory on the heap using `sbrk()` */
	size_t total_size = METADATA_SIZE + size;
	struct block_meta *block = (struct block_meta *) sbrk(total_size);
	if (block == (void *) -1)
		return NULL;

	/* Initialize the block metadata */
	block->size = size;
	block->status = STATUS_ALLOC;
	block->next = NULL;

	/* Add the block to the *end* of the linked list */
	if (global_base == NULL) {
		global_base = block;
	} else {
		struct block_meta *curr_block = global_base;
		while (curr_block->next != NULL)
			curr_block = curr_block->next;
		curr_block->next = block;
	}

	return (void *)(block + 1);
}

void *mmap_alloc(size_t size)
{
	size_t total_size = METADATA_SIZE + size;
	struct block_meta *block = (struct block_meta *) mmap(NULL, total_size,
											PROT_READ | PROT_WRITE,
											MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (block == (void *) -1)
		return NULL;

	block->size = size;
	block->status = STATUS_MAPPED;
	block->next = NULL;
	
	/* Add the block to the *begging* of the linked list */
	if (global_base == NULL) {
		global_base = block;
	} else {
		block->next = global_base;
		global_base = block;
	}

	return (void *)(block + 1);
}

void *os_malloc(size_t size)
{
	/* Check if the requested size is valid */
	if (size <= 0)
		return NULL;
	
	/* Align the given `size` to the next multiple of 8 */
	size = ALIGN(size);

	void *res = NULL;
	/* Alloc with `sbrk()` */
    if (size + METADATA_SIZE < threshold) {
		/* Initialize the heap for the first time */
		if (!heap_initialized)
			res = prealloc_heap();

		/* Coalesce adjacent free blocks */
		coalesce_blocks();
		
		/* Allocate on a free block */
		res = alloc_on_free_block(size);
		if (res != NULL)
			return res;
		
		/* Expand the last block */
		res = expand_last_block(size);
		if (res != NULL)
			return res;

		/* Allocate memory using `sbrk()` */
		return sbrk_alloc(size);
	}

	/* Allocate memory using `mmap()` */
	return mmap_alloc(size);
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;

	/* Find the metadata block for the given ptr */
	struct block_meta *block_ptr = (struct block_meta *) ptr - 1;


	if (block_ptr->status == STATUS_MAPPED) {
		/* The block was allocated using `mmap()` */
		if (munmap(block_ptr, METADATA_SIZE + block_ptr->size) == -1) {
			return;
		}
	} else if (block_ptr->status == STATUS_ALLOC) {
		/* The block was allocated using `sbrk()` */
		block_ptr->status = STATUS_FREE;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (nmemb == 0 || size == 0)
		return NULL;
	
	size_t payload_size = nmemb * size; // [TODO]: Check for overflow
	threshold = CALLOC_THRESHOLD;
	void *ptr = os_malloc(payload_size);
	threshold = MMAP_THRESHOLD;
	if (ptr == NULL)
		return NULL;
	memset(ptr, 0, payload_size);
	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	return NULL;
}
