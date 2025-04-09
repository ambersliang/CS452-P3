#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>
#include <signal.h>
#include <execinfo.h>
#include <unistd.h>
#include <time.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif

#include "lab.h"

#define handle_error_and_die(msg) \
    do                            \
    {                             \
        perror(msg);              \
        raise(SIGKILL);           \
    } while (0)

/**
 * @brief Convert bytes to the correct K value
 *
 * @param bytes the number of bytes
 * @return size_t the K value that will fit bytes
 */
size_t btok(size_t bytes)
{
    size_t needed_bytes = bytes + sizeof(struct avail);

    size_t k = SMALLEST_K;

    while ((UINT64_C(1) << k) < needed_bytes)
    {
        if (k >= MAX_K - 1) // Prevent overflow/infinite loop if size is huge
            break;
        k++;
    }

    if (k < SMALLEST_K)
    {
        k = SMALLEST_K;
    }

    return k;
}

struct avail *buddy_calc(struct buddy_pool *pool, struct avail *buddy)
{
    // Check for valid inputs
    if (!pool || !pool->base || !buddy)
    {
        return NULL;
    }

    // Get the kval of the buddy block
    size_t k = buddy->kval;

    // Calculate the block size, using 2^k
    size_t block_size = UINT64_C(1) << k;

    // Calculate the offset of the buddy block, or how far the block is from the start of the pool base
    uintptr_t block_offset = (uintptr_t)buddy - (uintptr_t)pool->base;

    // Calculate the buddy's offset using XOR
    uintptr_t buddy_offset = block_offset ^ block_size;

    // Return memory address of the buddy block
    return (struct avail *)((uintptr_t)pool->base + buddy_offset);
}

void *buddy_malloc(struct buddy_pool *pool, size_t size)
{
    // Check for valid inputs
    if (size == 0 || pool == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }

    // Convert the requested size using btok
    size_t k = btok(size);

    // Check if there is a block available
    size_t current_k = k;

    // Find the smallest available block that's large enough
    while (current_k <= pool->kval_m && pool->avail[current_k].next == &pool->avail[current_k])
    {
        current_k++;
    }

    // Out of memory for the block, return NULL
    if (current_k > pool->kval_m)
    {
        errno = ENOMEM;
        return NULL;
    }

     // Split blocks until we reach the desired size
    while (current_k > k)
    {
        // Get the block to split
        struct avail *block = pool->avail[current_k].next;
        
        // Remove it from the free list
        block->next->prev = block->prev;
        block->prev->next = block->next;

        current_k--;
        size_t size_half = UINT64_C(1) << current_k;
        struct avail *buddy = (struct avail *)((uintptr_t)block + size_half);

        // Initialize the buddy block
        buddy->tag = BLOCK_AVAIL;
        buddy->kval = current_k;
        
        // Add buddy to the free list at the new size class
        buddy->next = pool->avail[current_k].next;
        buddy->prev = &pool->avail[current_k];
        pool->avail[current_k].next->prev = buddy;
        pool->avail[current_k].next = buddy;

        // Put original block to in the new smaller size class
        block->kval = current_k;
        block->next = &pool->avail[current_k];
        block->prev = &pool->avail[current_k];
        pool->avail[current_k].next = block;
        pool->avail[current_k].prev = block;
    }

    // Allocate a block of the desired size class
    struct avail *block = pool->avail[k].next;
    block->tag = BLOCK_RESERVED;

    block->next->prev = block->prev;
    block->prev->next = block->next;

    // Return a pointer to the usable memory
    return (void *)((uintptr_t)block + sizeof(struct avail));
}

void buddy_free(struct buddy_pool *pool, void *ptr)
{
    // Check for valid inputs
    if (ptr == NULL || pool == NULL)
        return;

    // Move back to the start of the block metadata
    struct avail *block = (struct avail *)((uintptr_t)ptr - sizeof(struct avail));
    
    // Get kval of the block
    size_t k = block->kval;

    // Mark it as available
    block->tag = BLOCK_AVAIL;

    // Coalesce with buddy blocks if possible
    while (k < pool->kval_m)
    {
        // Find the buddy block of the current block
        struct avail *buddy = buddy_calc(pool, block);

        if (buddy->tag != BLOCK_AVAIL || buddy->kval != k)
            break;

        // Remove buddy from its free list
        buddy->next->prev = buddy->prev;
        buddy->prev->next = buddy->next;

        if (buddy < block)
        {
            block = buddy;
        }
        
        k++;
        block->kval = k;
    }

    // Insert the block back into the available list
    block->next = pool->avail[k].next;
    block->prev = &pool->avail[k];
    pool->avail[k].next->prev = block;
    pool->avail[k].next = block;
}

/**
 * @brief This is a simple version of realloc.
 *
 * @param poolThe memory pool
 * @param ptr  The user memory
 * @param size the new size requested
 * @return void* pointer to the new user memory
 */
void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size)
{
    // Required for Grad Students
    // Optional for Undergrad Students
}

void buddy_init(struct buddy_pool *pool, size_t size)
{
    size_t kval = 0;
    if (size == 0)
        kval = DEFAULT_K;
    else
        kval = btok(size);

    if (kval < MIN_K)
        kval = MIN_K;
    if (kval > MAX_K)
        kval = MAX_K - 1;

    // make sure pool struct is cleared out
    memset(pool, 0, sizeof(struct buddy_pool));
    pool->kval_m = kval;
    pool->numbytes = (UINT64_C(1) << pool->kval_m);
    // Memory map a block of raw memory to manage
    pool->base = mmap(
        NULL,                        /*addr to map to*/
        pool->numbytes,              /*length*/
        PROT_READ | PROT_WRITE,      /*prot*/
        MAP_PRIVATE | MAP_ANONYMOUS, /*flags*/
        -1,                          /*fd -1 when using MAP_ANONYMOUS*/
        0                            /* offset 0 when using MAP_ANONYMOUS*/
    );
    if (MAP_FAILED == pool->base)
    {
        handle_error_and_die("buddy_init avail array mmap failed");
    }

    // Set all blocks to empty. We are using circular lists so the first elements just point
    // to an available block. Thus the tag, and kval feild are unused burning a small bit of
    // memory but making the code more readable. We mark these blocks as UNUSED to aid in debugging.
    for (size_t i = 0; i <= kval; i++)
    {
        pool->avail[i].next = pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].kval = i;
        pool->avail[i].tag = BLOCK_UNUSED;
    }

    // Add in the first block
    pool->avail[kval].next = pool->avail[kval].prev = (struct avail *)pool->base;
    struct avail *m = pool->avail[kval].next;
    m->tag = BLOCK_AVAIL;
    m->kval = kval;
    m->next = m->prev = &pool->avail[kval];
}

void buddy_destroy(struct buddy_pool *pool)
{
    int rval = munmap(pool->base, pool->numbytes);
    if (-1 == rval)
    {
        handle_error_and_die("buddy_destroy avail array");
    }
    // Zero out the array so it can be reused it needed
    memset(pool, 0, sizeof(struct buddy_pool));
}

#define UNUSED(x) (void)x

/**
 * This function can be useful to visualize the bits in a block. This can
 * help when figuring out the buddy_calc function!
 */
static void printb(unsigned long int b)
{
    size_t bits = sizeof(b) * 8;
    unsigned long int curr = UINT64_C(1) << (bits - 1);
    for (size_t i = 0; i < bits; i++)
    {
        if (b & curr)
        {
            printf("1");
        }
        else
        {
            printf("0");
        }
        curr >>= 1L;
    }
}
