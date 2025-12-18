# Neshta样本分析

> **来源**: https://forum.butian.net/share/2820  
> **文章ID**: 2820

---

前言
--

前段时间群里一位师傅开远程桌面暴露`3389端口`时被人打了，然后上传了一个勒索程序，并触发了，在该师傅一番抢救后留下了一个样本，丢到微步上看了看之前好像还没人提交，猜测应该是某种方式内嵌的一个样本。然后找该师傅要了个被杀毒处理后剩下的东西看了看。

![](images/attach-13fb3784889c3a00399f9fb261fe6f8d4a70965b.png)

> 分析之前样本就被Windows Defender识别为 Neshta.A，但是换到火绒下又是 Neshta.C，有点摸不着头脑，同时网上相关资料也比较少，只能自己分析看看了

7z 程序分析
-------

> 样本哈希：8acf5c0049c39a19d42c66c1769874726789160438cec6ceeeb877ce805529d3

样本其本身是一个 7z 压缩的自解压程序，但是中间会释放一个可执行程序。根据这个特征又是MZP勒索了...但是本样本却是Neshta木马...

![](images/attach-a685c1e222f6d99c23f15e47ee90f24561c70eb9.png)

经过多次在虚拟机里测试，尝试运行此自解压程序，同时开启`Process Monitor`来监控对应程序操作，也没观察到对应释放的操作过程，这就有点奇怪了...

但是输入错误的密码可以大致窥探到内压缩的程序：

![](images/attach-ee3285982fbb47d6d685c285c794f6fa9b7fb1ba.png)

感觉上可能也就vbs以及bat程序有威胁？

> 但是也不知道密码是个啥...

无奈之举，只能硬看大几个兆的文件，来找不同了，比较遗憾的是盯了许久没有多大进度有点破防了，乖乖的从沙箱分析提取出的程序进行下载了...最抽象的是从沙箱下载下来的同名文件使用`Bindiff`来确定对应的差异，对应存在的不同点的函数只是简单的返回个数字...

![](images/attach-aa1a2e390208c8ea346f6373dd8e8144c90f5977.png)

就很奇怪？有点琢磨不透这个东西到底是怎么释放的文件，同时也找不到`svchost.com`这个玩意...

再次下载沙箱的东西，准备分析一下本体`svchost.com`干了啥东西...

对于`svchost.com`这个文件就出现的比较早了，最早提交分析是 2021年12月 出现的，那就是说明这个东西依然在利用

> 对应哈希：cab9a40acca9666c85d6f1712e97622b7982a14622b017210bfa155431de75b5

![](images/attach-f481996227d79412145c05f6291baff29318c241.png)

svchost.com 程序分析
----------------

这是一个`Delphi`写的东西，拿IDA分析一下，一些函数没办法识别出来，看对应的库函数有点难受。查了一下资料，有推荐使用`DEDE`来进行反编译逆向，这个工具可能有些年头了，又找了一下找到个`IDR`来进行`Delphi`的反编译

> [crypto2011/IDR: Interactive Delphi Reconstructor (github.com)](https://github.com/crypto2011/IDR)

用了用发现甚至不如IDA...只能显示汇编，于是在IDA里折腾了...

首先要做的便是让IDA导入`Delphi`的一些库

File -> Load File -> FLIRT Signature File

之后我们加入对应的库

![](images/attach-a24bc491abc0dd4d4558e7d0676d3291fde2d33a.png)

之后重新加载一下就可以看到一部分的库函数，虽然还是比较难看，但聊胜于无

对于`Delphi`所编写的程序，一般来说这块在分析时不用太关心，猜测为设置对应的异常处理

```php
v4 \= &savedregs;  
v3 \= (LPDWORD)&loc\_408220;  
ExceptionList \= NtCurrentTeb()\->NtTib.ExceptionList;  
\_\_writefsdword(0, (unsigned int)&ExceptionList);
```

之后比较显眼的便是下面的几个函数：

![](images/attach-f36b4396a092344983f80ab2324692983597e880.png)

### DecodeData

![](images/attach-c2ae3adf684ef4053e808fcc23ce5470796714b5.png)

其调用了一个伪随机来进行异或解密数据，可以直接调试拿一下数据，之后便有了后面的注释信息

### sub\_404AE8

此函数用来进入判断是否为大文件进而释放的，其本质上是获取了一个启动路径信息，之后进入到内部的`sub_406FE4`进行下一轮的分支判断

### sub\_406FE4

此函数用来获取到对应文件的扩展名(如：.exe、.pdf)，之后进行比较判断当前执行的程序是否为exe，如果是则进入分支内部

![](images/attach-3fa15816c3c2422686798817c2ffe406d5ac1eb9.png)

### sub\_407D9C

此函数大致判断了对应执行的文件是否为一个大文件(核心本体大小为40.5kb，如果大于此则为大文件)，即通过文件的大小来判断是否嵌入在其他程序上，如果是则将其进行释放，反之则将其感染(于`sub_4079A0`进行)

### sub\_4071D0

具体实现感染的部分，将自身PE进行嵌入

![](images/attach-078097f52bbd3075724ad0d6fec336938e4c0aea.png)

比较有意思的是其似乎还会获取对应的`ico`图标来将自身修改后的程序进行一个伪装，之前测试的时候似乎出现了程序图标加载不出来的问题，或许是这块调试的时候突然被`Windows Defender`干掉了的原因？

### sub\_4079A0

这一部分主要便是感染了，会在内存中将`svchost.com`进行解密出来，并将其进行读入内存创建对应的注册表项目

```php
HKEY\_LOCAL\_MACHINE\\SOFTWARE\\Classes\\exefile\\shell\\open\\command C:\\\\Windows\\\\svchost.com "%1" %\*
```

![](images/attach-5b89d37a616b2a0a95ebb0d0f13a8c6edb8c4b4e.png)

### sub\_40759C

![](images/attach-d8cea9b9921b045990bc799060dddecdf3864482.png)

这块便是在对应用户处创建一个`tmp5023.tmp`文件，随后创建一个互斥量来对逻辑盘信息进行遍历(`sub_406D40`)，而其选择感染的逻辑盘中也有选择：

![](images/attach-99270b1c3d1b485b37cab80446344073590d66d7.png)

其会避开A、B盘以及CD-ROM驱动器

之后进入到`WebForm::_16623`内部进行获取对应盘下的所有文件了，通过拼接盘号以及`*.*`来进行获取内容

![](images/attach-800f23acac0b1ccae3ccdd33a3ea0d176ee67d4f.png)

### sub\_405634

![](images/attach-f00b54859390377e67259b8a187fc29983dd71e3.png)

其会获取对应路径文件，同时递归往下进行查找对应的内容

![image-20231130145336041](images/attach-f659fd5c242306e0186c85cac1582e8719080d44.png)

### sub\_406E0C

此函数下会创建一个tmp5023.tmp

![](images/attach-47648e92511283276fa3d0dc4722a39270a0182d.png)

而在`sub_406E94`对其进行读取对应的 8 个字节

![](images/attach-a6b0efb7553ff4d62cbcdae34b9880eebb8b31fc.png)

有点搞不懂读入的对应文件内容是具体什么含义，感觉可能是时间戳之类的东西

样本技术信息
------

此样本本质上通过植入自身文件来进行感染，属于感染型样本。整体感觉上此程序更像是一个恶意程序启动器，以及判断文件是否被感染

其会释放以下文件：

```php
xxx.exe   # 原先被感染的干净程序  
tmp5023.tmp  # 暂时还不知道干什么用   
svchost.com  # 检测是否为PE文件以及进行感染和释放  
%User Temp%\\3582-490\\    # 创建此文件夹
```

之后会创建以下进程：

```php
%User Temp%\\3582-490\\xxx.exe      # xxx.exe为恶意程序进程
```

创建互斥体：`MutexPolesskayaGlush`用来确保一次只会运行一个副本

主要感染对象：exe文件

避免感染含有以下字符串的对象：

```php
PROGRA~1  
%Windows%  
%Temp%
```

避免感染下列文件大小：

```php
小于 41,472 字节或大于 10,000,000 字节的文件
```

避免感染以下驱动器的文件：

```php
A:\\  
B:\\  
CD-ROM
```

解决方案
----

在`HKEY_MACHINE\SOFTWARE\Classes\exefile\shell\open\`注册表项中的默认选项进行以下修改：

```php
From: (Default) = %Windows%\\svchost.com "%1" %\*"  
To：(Default) = "%1" %\*"
```

删除对应的恶意软件、以及临时文件目录下的

```php
svchost.com  
tmp5023.tmp
```

同时安装对应的杀毒软件进行全盘扫描，将对应恶意程序进行清除

参考
--

[PE\_NESHTA.A - 威胁百科全书 - Trend Micro CN](https://www.trendmicro.com.cn/vinfo/cn/threat-encyclopedia/malware/pe_neshta.a)

[PE\_NESHTA.A-O - Threat Encyclopedia (trendmicro.com)](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/PE_NESHTA.A-O/?_ga=2.8686908.864178295.1701322896-1254639615.1700750343)

[Neshta Malware - Malware removal instructions (updated) (pcrisk.com)](https://www.pcrisk.com/removal-guides/16249-neshta-malware)
