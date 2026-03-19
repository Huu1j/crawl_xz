# 在pwn中malloc扮演的角色(1)-先知社区

> **来源**: https://xz.aliyun.com/news/17328  
> **文章ID**: 17328

---

# 在pwn中malloc扮演的角色(1)

学习这么久的pwn了,二进制也接触这么长时间了,想要也要细细观摩一下源码,仔细看看他的内部运行逻辑才是.

## chunk结构

glibc中所有malloc源码作者都在用自己的方式解读,希望读者都能慢慢理解

```
struct malloc_chunk {

  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

### 基础概念和名词

```
#define chunk2mem(p)   ((void*)((char*)(p) + 2*SIZE_SZ))     //指向所分配的内存所在处 
#define mem2chunk(mem) ((mchunkptr)((char*)(mem) - 2*SIZE_SZ))     //指针所在处 

/* The smallest possible chunk */
#define MIN_CHUNK_SIZE        (offsetof(struct malloc_chunk, fd_nextsize))   //64位0x20  32位0x10 

/* The smallest size we can malloc is an aligned minimal chunk */

#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))

/* Check if m has acceptable alignment */

#define aligned_OK(m)  (((unsigned long)(m) & MALLOC_ALIGN_MASK) == 0)

#define misaligned_chunk(p) \
  ((uintptr_t)(MALLOC_ALIGNMENT == 2 * SIZE_SZ ? (p) : chunk2mem (p)) \
   & MALLOC_ALIGN_MASK)


/*
   Check if a request is so large that it would wrap around zero when
   padded and aligned. To simplify some other code, the bound is made
   low enough so that adding MINSIZE will also not wrap around zero.
 */

#define REQUEST_OUT_OF_RANGE(req)                                 \
  ((unsigned long) (req) >=						      \
   (unsigned long) (INTERNAL_SIZE_T) (-2 * MINSIZE))

/* pad request bytes into a usable size -- internal version */

#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/*  Same, except also perform argument check */

#define checked_request2size(req, sz)                             \   //判断大小-32<=都可以   -31~0不可以申请 
  if (REQUEST_OUT_OF_RANGE (req)) {					      \
      __set_errno (ENOMEM);						      \
      return 0;								      \
    }									      \
  (sz) = request2size (req);

/*
   --------------- Physical chunk operations ---------------
 */


/* size field is or'ed with PREV_INUSE when previous adjacent chunk in use */
#define PREV_INUSE 0x1

/* extract inuse bit of previous chunk */
#define prev_inuse(p)       ((p)->size & PREV_INUSE)      //判断最低位的使用状态 
#define IS_MMAPPED 0x2                  //判断倒数第二位 
#define chunk_is_mmapped(p) ((p)->size & IS_MMAPPED)    //check chunk是否是mmap()申请的
#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
//SIZE_BITS = 0x1 | 0x2 | 0x4
//          = 0x7            // 0111
#define chunksize(p)         ((p)->size & ~(SIZE_BITS))


/* Ptr to next physical malloc_chunk. */
#define next_chunk(p) ((mchunkptr) (((char *) (p)) + ((p)->size & ~SIZE_BITS)))

/* Ptr to previous physical malloc_chunk */
#define prev_chunk(p) ((mchunkptr) (((char *) (p)) - ((p)->prev_size)))
//变化之后指针如何找到nextchunk和prevsize的变化

```

基本上重要的概念就在上面了,接下来是一些函数的讲解

```
#define unlink(AV, P, BK, FD) {                                            \
    FD = P->fd;								      \
    BK = P->bk;								      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))	/* 漏洞检查 */ 	      \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
    else {								      \
        FD->bk = BK;							      \
        BK->fd = FD;							      \
        if (!in_smallbin_range (P->size)/*  判断是否是smallbin  */	      \
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {		      \
        if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)	      \
        || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
          malloc_printerr (check_action,				      \
                   "corrupted double-linked list (not small)",    \
                   P, AV);					      \
            if (FD->fd_nextsize == NULL)/*指针是否为空*/ {				      \
                if (P->fd_nextsize == P)/* 看是否指向自己  */	     \
                  FD->fd_nextsize = FD->bk_nextsize = FD;		      \
                else {							      \/*  更新指针  */
                    FD->fd_nextsize = P->fd_nextsize;		      \
                    FD->bk_nextsize = P->bk_nextsize;			      \
                    P->fd_nextsize->bk_nextsize = FD;			      \
                    P->bk_nextsize->fd_nextsize = FD;			      \
                  }							      \
              } else {	/*不为空执行下面的更新内容*/						      \
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;		      \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;		      \
              }								      \
          }								      \
      }									      \
}
上面的代码展示了unlink的具体过程,而实际上,最关键的点在于如何绕过FD->bk != P || BK->fd != P
```

下面是关于各种bins

```
/*
   Indexing

    Bins for sizes < 512 bytes contain chunks of all the same size, spaced
    8 bytes apart. Larger bins are approximately logarithmically spaced:

    64 bins of size       8
    32 bins of size      64
    16 bins of size     512
     8 bins of size    4096
     4 bins of size   32768
     2 bins of size  262144
     1 bin  of size what's left

    There is actually a little bit of slop in the numbers in bin_index
    for the sake of speed. This makes no difference elsewhere.

    The bins top out around 1MB because we expect to service large
    requests via mmap.

    Bin 0 does not exist.  Bin 1 is the unordered list; if that would be
    a valid chunk size the small bins are bumped up one.
 */

#define NBINS             128
#define NSMALLBINS         64
#define SMALLBIN_WIDTH    MALLOC_ALIGNMENT
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)
#define MIN_LARGE_SIZE    ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)
Indexing:
该部分的主题是内存块的索引方式。
Bins for sizes < 512 bytes:
对于小于 512 字节的内存块，索引采用相同大小的块，间隔 8 字节。这意味着这些小块是均匀分布的。
Larger bins:
对于更大的块，索引采用对数间隔，以便更有效地管理内存。不同大小的 bin 数量如下：
64 个 bin，大小为 8 字节
32 个 bin，大小为 64 字节
16 个 bin，大小为 512 字节
8 个 bin，大小为 4096 字节
4 个 bin，大小为 32768 字节
2 个 bin，大小为 262144 字节
1 个 bin，大小为剩余的内存
Slop in the numbers:
在 bin_index 中存在一些“冗余”数字，以提高速度，这通常不会影响其他地方的逻辑。
Top out around 1MB:
对于大于 1MB 的请求，通常使用 mmap 来处理，因此 bin 的上限设置在 1MB 处。
Bin 0 does not exist:
表示 bin 0 是无效的。bin 1 是无序列表，用于处理较小的内存块。
宏定义分析
#define NBINS 128:
定义总共使用的 bin 数量为 128。
#define NSMALLBINS 64:
定义小型 bin 的数量为 64。
#define SMALLBIN_WIDTH MALLOC_ALIGNMENT:
定义小型 bin 的宽度为内存分配对齐（MALLOC_ALIGNMENT），这通常是一个常量，表示内存分配的对齐要求。
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ):
这个宏用于检查是否需要进行小型 bin 的调整，如果内存对齐大于两倍的 SIZE_SZ，则需要进行调整。
#define MIN_LARGE_SIZE ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH):
计算最小的大型内存块大小，考虑到小型 bin 的数量和可能的调整。这将影响后续的大型内存请求的处理。
```

### libc\_malloc函数细节

```
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);   //malloc_hook传到hook的指针处
  if (__builtin_expect (hook != NULL, 0))             //检查hook此处的指针是否为空,若为空则直接退出,不为空则执行malloc处的代码,这也就解释了malloc_hook的攻击方式
    return (*hook)(bytes, RETURN_ADDRESS (0));

  arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);
  /* Retry with another arena only if we were able to find a usable arena
     before.  */
  if (!victim && ar_ptr != NULL)          //此时int_malloc如果申请成功就跳过执行下面失败则重新分配arena在重新调用malloc
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }

  if (ar_ptr != NULL)
    (void) mutex_unlock (&ar_ptr->mutex);

  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim)));
  return victim;
}
libc_hidden_def (__libc_malloc)
```

### 那我们接下来继续看int\_malloc函数

```
static void *
_int_malloc (mstate av, size_t bytes)
{
  INTERNAL_SIZE_T nb;               /* normalized request size */
  unsigned int idx;                 /* associated bin index */
  mbinptr bin;                      /* associated bin */

  mchunkptr victim;                 /* inspected/selected chunk */
  INTERNAL_SIZE_T size;             /* its size */
  int victim_index;                 /* its bin index */

  mchunkptr remainder;              /* remainder from a split */
  unsigned long remainder_size;     /* its size */

  unsigned int block;               /* bit map traverser */
  unsigned int bit;                 /* bit map traverser */
  unsigned int map;                 /* current word of binmap */

  mchunkptr fwd;                    /* misc temp for linking */
  mchunkptr bck;                    /* misc temp for linking */

  const char *errstr = NULL;

INTERNAL_SIZE_T nb:
用于存储标准化的请求大小，可能会考虑对齐和其他因素，以确保正确的内存分配。
unsigned int idx:
关联的 bins 索引，表示在 bins 数组中查找的索引位置。
mbinptr bin:
指向当前查找的 bin 结构体，bin 是一个存储多个空闲内存块的链表。
mchunkptr victim:
当前检查或选择的内存块，表示分配时可能会使用的内存区域。
INTERNAL_SIZE_T size:
该内存块的大小，用于决定是否可以满足请求的内存大小。
int victim_index:
受害者块的 bin 索引，指示该块在 bins 中的位置。
mchunkptr remainder:
从分割中得到的剩余内存块，表示如果内存块过大，可以将其分割并保留的部分。
unsigned long remainder_size:
剩余内存块的大小，用于管理分割后剩余的内存。
unsigned int block 和 unsigned int bit:
用于遍历位图的变量，通常用于跟踪哪些 bins 是空闲的。
unsigned int map:
当前的位图单元，表示 bins 中的空闲状态。
mchunkptr fwd 和 mchunkptr bck:
用于链接操作的临时变量，可能用于双向链表的管理。
const char *errstr:
用于存储错误信息的字符串指针，可能用于调试或错误处理。
checked_request2size (bytes, nb);             //把申请的大小转化为需要的chunk的大小 
```

## bins的分配

```
if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp = *fb;
      do
        {
          victim = pp;
          if (victim == NULL)
            break;
        }
      while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))
             != victim);
      if (victim != 0)
        {
          if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))            //1.检查a
            {
              errstr = "malloc(): memory corruption (fast)";
            errout:
              malloc_printerr (check_action, errstr, chunk2mem (victim), av);
              return NULL;
            }
          check_remalloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }

  /*
     If a small request, check regular bin.  Since these "smallbins"
     hold one size each, no searching within bins is necessary.
     (For a large request, we need to wait until unsorted chunks are
     processed to find best fit. But for small ones, fits are exact
     anyway, so we can check now, which is faster.)
   */

  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          if (victim == 0) /* initialization check */
            malloc_consolidate (av);
          else
            {
              bck = victim->bk;
    if (__glibc_unlikely (bck->fd != victim))
                {
                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }
              set_inuse_bit_at_offset (victim, nb);
              bin->bk = bck;
              bck->fd = bin;

              if (av != &main_arena)
                victim->size |= NON_MAIN_ARENA;
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }
    }
    首先是匹配fastbin然后更新链表,这里有一个检查a,判断申请的vitci的size是否与申请的idx相同,然后让所有指针调整到申请后的位置,smallbin操作与之相同(前提最开始都要获得对应的index)
  else
    {
      idx = largebin_index (nb);
      if (have_fastchunks (av))
        malloc_consolidate (av);
    }
对于largebin_chunk操作类似.先获得index,判断当前分配区的fast bins中是否包含chunk，如果存在，调用malloc_consolidate()函数合并fast bins中的chunk，并将这些空闲chunk加入unsorted bin中。
```
