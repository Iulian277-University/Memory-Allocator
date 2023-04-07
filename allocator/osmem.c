// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "helpers.h"

#include <stdbool.h> /* for bool */
#include <unistd.h> /* for sbrk() */
#include <sys/mman.h> /* for mmap() */


static struct block_meta *global_base = NULL; /* Head of the linked list */
static bool heap_initialized = false; /* Flag to check if the heap is initialized */
static size_t threshold = MMAP_THRESHOLD; /* Threshold for `mmap()` when `malloc()`ing or `calloc()`ing */

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

void coalesce_blocks()
{
    struct block_meta *curr_block = global_base;
	bool coalesced = false;

	do {
		coalesced = false;
		while (curr_block != NULL && curr_block->next != NULL) {
			if (curr_block->status == STATUS_FREE && curr_block->next->status == STATUS_FREE) {
				/* Coalesce adjacent free blocks */
				curr_block->size += METADATA_SIZE + curr_block->next->size;
				curr_block->next = curr_block->next->next;
				coalesced = true;
			} else {
				curr_block = curr_block->next;
			}
		}
		curr_block = global_base;
	} while (coalesced);
}

struct block_meta *find_best_free_block(size_t size)
{
	struct block_meta *current = global_base;
	struct block_meta *best_block = NULL;

	size = ALIGN(size);
	size_t best_fit_size = 0;
	while (current != NULL) {
		if (current->status == STATUS_FREE && current->size >= size) {
			/* Found a free block that can hold the requested size */
			size_t curr_fit_size = current->size - size;
			if (best_block == NULL || curr_fit_size < best_fit_size) {
				best_block = current;
				best_fit_size = curr_fit_size;
			}
		}
		current = current->next;
	}

	return best_block;
}

void *split_if_possible(struct block_meta *block, size_t size)
{
	size = ALIGN(size);

	/* Try to split the block */
	if (block->size - size > METADATA_SIZE + ALIGN(1)) {
		struct block_meta *temp = (struct block_meta *) ((char *) block + METADATA_SIZE + size);

		/* Include the `temp` block in the linked list */
		temp->next = block->next;
		block->next = temp;

		/* Update the `temp` block metadata */
		temp->size = block->size - (size + METADATA_SIZE);
		temp->status = STATUS_FREE;

		/* Update the `block` metadata */
		block->size = size;
	}

	/* Mark the `block` as allocated */
	block->status = STATUS_ALLOC;

	return (void *)(block + 1);
}

void *alloc_on_free_block(size_t size)
{
	struct block_meta *block = find_best_free_block(size);
	if (block == NULL)
		return NULL;
	
	/* Split the block if possible */
	return split_if_possible(block, size);
}


void *expand_last_block(size_t size)
{
	struct block_meta *last_block = global_base;
	if (last_block == NULL)
		return NULL;

	/* Find the last block in the linked list */
	while (last_block->next != NULL)
		last_block = last_block->next;

	/* Check if the last block is free */
	if (last_block->status != STATUS_FREE)
		return NULL;

	/* Align the size */
	size = ALIGN(size);

	/* Expand the heap */
	void *new_brk = sbrk(size - last_block->size);
	if (new_brk == (void *) -1)
		return NULL;

	/* Update the block metadata */
	last_block->size = size;
	last_block->status = STATUS_ALLOC;

	return (void *)(last_block + 1);
}

void *prealloc_heap()
{
	/* Initialize the heap for the first time */
	struct block_meta *block = (struct block_meta *) sbrk(ALIGN(PREALLOC_SIZE));
	if (block == (void *) -1)
		return NULL;
	
	block->size = PREALLOC_SIZE; // - METADATA_SIZE;
	block->status = STATUS_FREE;

	block->next = NULL;
	global_base = block;

	heap_initialized = true;
	
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
    if (METADATA_SIZE + size < threshold) {
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


void merge_adjacent_free_blocks(struct block_meta *block_ptr)
{
	struct block_meta *prev = NULL;
	struct block_meta *current = global_base;
	while (current != NULL) {
		/* Found the freed block */
		if (current == block_ptr) {
			/* Merge with the previous block */
			if (prev != NULL && prev->status == STATUS_FREE) {
				prev->size += METADATA_SIZE + current->size;
				prev->next = current->next;
				current = prev;
			}
			/* Merge with the next block */
			if (current->next != NULL && current->next->status == STATUS_FREE) {
				current->size += METADATA_SIZE + current->next->size;
				current->next = current->next->next;
			}
			break;
		}
		prev = current;
		current = current->next;
	}
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
	if (ptr == NULL)
		return os_malloc(size);

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	coalesce_blocks();

	struct block_meta *block_ptr = (struct block_meta *) ptr - 1;
	size_t old_size = block_ptr->size;

	if (block_ptr->status == STATUS_FREE)
		return NULL;

	/* Align the given `size` to the next multiple of 8 */
	size = ALIGN(size);


	/* The block was allocated with `mmap()` */
	if (block_ptr->status == STATUS_MAPPED) {
		void *new_ptr = os_malloc(size);
		if (new_ptr == NULL)
			return NULL;

		size_t copy_size = old_size < size ? old_size : size;
		memcpy(new_ptr, ptr, copy_size);

		os_free(ptr);
		return new_ptr;
	}
	
	/* Split the block (truncate it) */
	if (block_ptr->size >= size) {
		split_if_possible(block_ptr, size);
		return ptr;
	}
	
	
	/* Expand the block */
	if (block_ptr->status == STATUS_ALLOC && block_ptr->next != NULL && block_ptr->next->status == STATUS_FREE) {
		/* The next block is free */
		size_t new_size = block_ptr->size + METADATA_SIZE + block_ptr->next->size;
		if (new_size >= size) {
			/* Merge the next block with the current block */
			block_ptr->size = new_size;
			block_ptr->next = block_ptr->next->next;
			split_if_possible(block_ptr, size);
			return ptr;
		}
	}

	/* The block was allocated on the heap with `sbrk()` */
	if (block_ptr->status == STATUS_ALLOC) {
		void *new_ptr = os_malloc(size);
		if (new_ptr == NULL)
			return NULL;
			
		size_t copy_size = old_size < size ? old_size : size;
		memcpy(new_ptr, ptr, copy_size);
		
		struct block_meta *new_block_ptr = (struct block_meta *) new_ptr - 1;
		new_block_ptr->size = size;

		os_free(ptr);
		return (void *)(new_block_ptr + 1);
	}

	return NULL;
}
