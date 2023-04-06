// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "helpers.h"

#include <stdbool.h> /* for bool */
#include <unistd.h> /* for sbrk() */
#include <sys/mman.h> /* for mmap() */

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

	if (block->size - size > METADATA_SIZE + ALIGN(1)) {
		struct block_meta *temp = (struct block_meta *) ((char *) block + METADATA_SIZE + size);

		/* Include the `temp` block in the linked list */
		temp->next = block->next;
		block->next = temp;

		/* Update the `temp` block metadata */
		temp->size = block->size - (METADATA_SIZE + size);
		temp->status = STATUS_FREE;
	}

	/* Update the `block` metadata */
	block->size = size;
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
	size_t total_size = PREALLOC_SIZE;
	total_size = ALIGN(total_size);
	struct block_meta *block = (struct block_meta *) sbrk(total_size);
	if (block == (void *) -1)
		return NULL;
	
	block->size = PREALLOC_SIZE; // - METADATA_SIZE;
	block->status = STATUS_FREE;
	block->next = NULL;
	global_base = block;
	heap_initialized = 1;
	
	return (void *)(block + 1);
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
