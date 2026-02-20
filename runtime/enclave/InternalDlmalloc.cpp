#include "InternalDlmalloc.hpp"

struct malloc_chunk {
  size_t prev_foot;        /* Size of previous chunk (if free).  */
  size_t head;             /* Size and inuse bits. */
  struct malloc_chunk *fd; /* double links -- used only if free. */
  struct malloc_chunk *bk;
};

typedef struct malloc_chunk *mchunkptr;

#define FOOTERS 1

#define SIZE_T_SIZE (sizeof(size_t))

#define SIZE_T_ONE ((size_t)1)
#define SIZE_T_TWO ((size_t)2)
#define SIZE_T_FOUR ((size_t)4)
#define TWO_SIZE_T_SIZES (SIZE_T_SIZE << 1)

#if FOOTERS
#define CHUNK_OVERHEAD (TWO_SIZE_T_SIZES)
#else /* FOOTERS */
#define CHUNK_OVERHEAD (SIZE_T_SIZE)
#endif /* FOOTERS */

/* MMapped chunks need a second word of overhead ... */
#define MMAP_CHUNK_OVERHEAD (TWO_SIZE_T_SIZES)

#define PINUSE_BIT (SIZE_T_ONE)
#define CINUSE_BIT (SIZE_T_TWO)
#define FLAG4_BIT (SIZE_T_FOUR)
#define INUSE_BITS (PINUSE_BIT | CINUSE_BIT)
#define FLAG_BITS (PINUSE_BIT | CINUSE_BIT | FLAG4_BIT)

#define mem2chunk(mem) ((mchunkptr)((char *)(mem)-TWO_SIZE_T_SIZES))
#define is_inuse(p) (((p)->head & INUSE_BITS) != PINUSE_BIT)
#define is_mmapped(p) (((p)->head & INUSE_BITS) == 0)

#define chunksize(p) ((p)->head & ~(FLAG_BITS))

/* Get the internal overhead associated with chunk p */
#define overhead_for(p) (is_mmapped(p) ? MMAP_CHUNK_OVERHEAD : CHUNK_OVERHEAD)

size_t dlmalloc_usable_size(void *mem) {
  if (mem != 0) {
    mchunkptr p = mem2chunk(mem);
    if (is_inuse(p))
      return chunksize(p) - overhead_for(p);
  }
  return 0;
}