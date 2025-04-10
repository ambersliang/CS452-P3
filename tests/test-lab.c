#include <assert.h>
#include <stdlib.h>
#include <time.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif
#include "harness/unity.h"
#include "../src/lab.h"


void setUp(void) {
  // set stuff up here
}

void tearDown(void) {
  // clean stuff up here
}



/**
 * Check the pool to ensure it is full.
 */
void check_buddy_pool_full(struct buddy_pool *pool)
{
  //A full pool should have all values 0-(kval-1) as empty
  for (size_t i = 0; i < pool->kval_m; i++)
    {
      assert(pool->avail[i].next == &pool->avail[i]);
      assert(pool->avail[i].prev == &pool->avail[i]);
      assert(pool->avail[i].tag == BLOCK_UNUSED);
      assert(pool->avail[i].kval == i);
    }

  //The avail array at kval should have the base block
  assert(pool->avail[pool->kval_m].next->tag == BLOCK_AVAIL);
  assert(pool->avail[pool->kval_m].next->next == &pool->avail[pool->kval_m]);
  assert(pool->avail[pool->kval_m].prev->prev == &pool->avail[pool->kval_m]);

  //Check to make sure the base address points to the starting pool
  //If this fails either buddy_init is wrong or we have corrupted the
  //buddy_pool struct.
  assert(pool->avail[pool->kval_m].next == pool->base);
}

/**
 * Check the pool to ensure it is empty.
 */
void check_buddy_pool_empty(struct buddy_pool *pool)
{
  //An empty pool should have all values 0-(kval) as empty
  for (size_t i = 0; i <= pool->kval_m; i++)
    {
      assert(pool->avail[i].next == &pool->avail[i]);
      assert(pool->avail[i].prev == &pool->avail[i]);
      assert(pool->avail[i].tag == BLOCK_UNUSED);
      assert(pool->avail[i].kval == i);
    }
}

/**
 * Test allocating 1 byte to make sure we split the blocks all the way down
 * to MIN_K size. Then free the block and ensure we end up with a full
 * memory pool again
 */
void test_buddy_malloc_one_byte(void)
{
  fprintf(stderr, "->Test allocating and freeing 1 byte\n");
  struct buddy_pool pool;
  int kval = MIN_K;
  size_t size = UINT64_C(1) << kval;
  buddy_init(&pool, size);
  void *mem = buddy_malloc(&pool, 1);
  //Make sure correct kval was allocated
  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Tests the allocation of one massive block that should consume the entire memory
 * pool and makes sure that after the pool is empty we correctly fail subsequent calls.
 */
void test_buddy_malloc_one_large(void)
{
  fprintf(stderr, "->Testing size that will consume entire memory pool\n");
  struct buddy_pool pool;
  size_t bytes = UINT64_C(1) << MIN_K;
  buddy_init(&pool, bytes);

  //Ask for an exact K value to be allocated. This test makes assumptions on
  //the internal details of buddy_init.
  size_t ask = bytes - sizeof(struct avail);
  void *mem = buddy_malloc(&pool, ask);
  assert(mem != NULL);

  //Move the pointer back and make sure we got what we expected
  struct avail *tmp = (struct avail *)mem - 1;
  assert(tmp->kval == MIN_K);
  assert(tmp->tag == BLOCK_RESERVED);
  check_buddy_pool_empty(&pool);

  //Verify that a call on an empty tool fails as expected and errno is set to ENOMEM.
  void *fail = buddy_malloc(&pool, 5);
  assert(fail == NULL);
  assert(errno = ENOMEM);

  //Free the memory and then check to make sure everything is OK
  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Tests to make sure that the struct buddy_pool is correct and all fields
 * have been properly set kval_m, avail[kval_m], and base pointer after a
 * call to init
 */
void test_buddy_init(void)
{
  fprintf(stderr, "->Testing buddy init\n");
  //Loop through all kval MIN_k-DEFAULT_K and make sure we get the correct amount allocated.
  //We will check all the pointer offsets to ensure the pool is all configured correctly
  for (size_t i = MIN_K; i <= DEFAULT_K; i++)
    {
      size_t size = UINT64_C(1) << i;
      struct buddy_pool pool;
      buddy_init(&pool, size);
      check_buddy_pool_full(&pool);
      buddy_destroy(&pool);
    }
}

/**
 * Test buddy_calc by allocating a block, computing its buddy,
 * and making sure the buddy address is correct based on XOR logic.
 */
void test_buddy_calc_correctness(void)
{
  fprintf(stderr, "->Testing buddy_calc correctness\n");
  struct buddy_pool pool;
  buddy_init(&pool, UINT64_C(1) << MIN_K);

  void *mem = buddy_malloc(&pool, 1);
  struct avail *block = (struct avail *)((uintptr_t)mem - sizeof(struct avail));
  struct avail *buddy = buddy_calc(&pool, block);

  // Check if the buddy is offset exactly 2^kval from the block
  uintptr_t offset1 = (uintptr_t)block - (uintptr_t)pool.base;
  uintptr_t offset2 = (uintptr_t)buddy - (uintptr_t)pool.base;
  size_t block_size = UINT64_C(1) << block->kval;

  assert((offset1 ^ offset2) == block_size);

  buddy_free(&pool, mem);
  buddy_destroy(&pool);
}

/**
 * Try to allocate more memory than the pool has.
 * Should always fail.
 */
void test_buddy_malloc_too_large(void)
{
  fprintf(stderr, "->Testing allocation request larger than pool\n");
  struct buddy_pool pool;
  size_t total = UINT64_C(1) << MIN_K;
  buddy_init(&pool, total);

  // Ask for something way too big
  void *mem = buddy_malloc(&pool, total * 2);
  assert(mem == NULL);
  assert(errno == ENOMEM);

  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Test memory fragmentation by allocating and freeing blocks of various sizes
 * to simulate fragmentation and ensure proper block coalescing.
 */
void test_buddy_memory_fragmentation(void)
{
  fprintf(stderr, "->Testing memory fragmentation\n");
  struct buddy_pool pool;
  size_t size = UINT64_C(1) << (MIN_K + 2); 
  buddy_init(&pool, size);

  void *block1 = buddy_malloc(&pool, 16);
  void *block2 = buddy_malloc(&pool, 32);
  void *block3 = buddy_malloc(&pool, 64);
  void *block4 = buddy_malloc(&pool, 128);
  
  buddy_free(&pool, block1);
  buddy_free(&pool, block3);
  
  void *block5 = buddy_malloc(&pool, 32);  // Should fit in the freed space from block1 or block3
  void *block6 = buddy_malloc(&pool, 16);  // Should fit in the freed space from block1
  
  // Free all blocks
  buddy_free(&pool, block2);
  buddy_free(&pool, block4);
  buddy_free(&pool, block5);
  buddy_free(&pool, block6);

  // Check if memory pool is full
  check_buddy_pool_full(&pool);

  buddy_destroy(&pool);
}

/**
 * Test allocating and freeing multiple blocks of different sizes
 * to simulate a real-world usage scenario with many allocations and frees.
 */
void test_buddy_malloc_multiple_blocks(void)
{
  fprintf(stderr, "->Testing multiple allocations and frees\n");
  struct buddy_pool pool;
  size_t size = UINT64_C(1) << (MIN_K + 2); // Initialize a pool large enough for multiple blocks
  buddy_init(&pool, size);

  void *block1 = buddy_malloc(&pool, 64);
  void *block2 = buddy_malloc(&pool, 128);
  void *block3 = buddy_malloc(&pool, 256);
  void *block4 = buddy_malloc(&pool, 512);

  buddy_free(&pool, block1);
  buddy_free(&pool, block3);
  buddy_free(&pool, block2);
  buddy_free(&pool, block4);

  // Check the pool is back to its initial state
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Test double-freeing a block and ensure it doesn't result in undefined behavior.
 */
void test_buddy_double_free(void)
{
  fprintf(stderr, "->Testing double free\n");
  struct buddy_pool pool;
  size_t size = UINT64_C(1) << (MIN_K + 2); // Initialize a pool large enough
  buddy_init(&pool, size);

  void *block = buddy_malloc(&pool, 64);
  buddy_free(&pool, block);

  // Double free: should not cause undefined behavior
  buddy_free(&pool, block); // Free again without allocation

  // Check the pool is still valid after double-free
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Test allocating a block that will fit in the smallest block size (MIN_K).
 * This ensures that the smallest block allocation logic is correct.
 */
void test_buddy_malloc_smallest_block(void)
{
  fprintf(stderr, "->Testing allocation of smallest block size\n");
  struct buddy_pool pool;
  size_t size = UINT64_C(1) << MIN_K; // Initialize pool just big enough for the smallest block
  buddy_init(&pool, size);

  void *mem = buddy_malloc(&pool, 1); // Request a block of size 1 byte
  assert(mem != NULL); // Should successfully allocate 1 byte

  struct avail *block = (struct avail *)((uintptr_t)mem - sizeof(struct avail));
  assert(block->kval == MIN_K);
  assert(block->tag == BLOCK_RESERVED);

  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Test that buddy malloc fails gracefully when asking for more memory than available.
 * Ensure that errno is set to ENOMEM.
 */
void test_buddy_malloc_fail(void)
{
  fprintf(stderr, "->Testing allocation failure due to insufficient memory\n");
  struct buddy_pool pool;
  size_t size = UINT64_C(1) << MIN_K; // Initialize a small pool
  buddy_init(&pool, size);

  // Try to allocate more memory than the pool can handle
  void *mem = buddy_malloc(&pool, size * 2); 
  assert(mem == NULL);  // Should fail
  assert(errno == ENOMEM); // Should set errno to ENOMEM

  buddy_destroy(&pool);
}


int main(void) {
  time_t t;
  unsigned seed = (unsigned)time(&t);
  fprintf(stderr, "Random seed:%d\n", seed);
  srand(seed);
  printf("Running memory tests.\n");

  UNITY_BEGIN();
  RUN_TEST(test_buddy_init);
  RUN_TEST(test_buddy_malloc_one_byte);
  RUN_TEST(test_buddy_malloc_one_large);
  RUN_TEST(test_buddy_calc_correctness);
  RUN_TEST(test_buddy_malloc_too_large);
  RUN_TEST(test_buddy_memory_fragmentation);
  RUN_TEST(test_buddy_malloc_multiple_blocks); 
  RUN_TEST(test_buddy_double_free); 
  RUN_TEST(test_buddy_malloc_smallest_block); 
  RUN_TEST(test_buddy_malloc_fail);
return UNITY_END();
}
