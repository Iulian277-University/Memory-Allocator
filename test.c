#include <stdio.h>

struct block_meta {
	size_t size;
	int status;
	struct block_meta *next;
};

int main()
{
    printf("%lu\n", sizeof(size_t));
    printf("%lu\n", sizeof(int));
    printf("%lu\n", sizeof(struct block_meta *));
    printf("%lu\n", sizeof(struct block_meta));
    return 0;
}
