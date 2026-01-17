# 新的 Diamorphine rootkit 变体在野外被发现

> **来源**: https://forum.butian.net/share/3113  
> **文章ID**: 3113

---

翻译：<https://decoded.avast.io/davidalvarez/new-diamorphine-rootkit-variant-seen-undetected-in-the-wild/>  
恶意软件中的代码重用现象非常普遍，尤其是对于那些开发难度大或难以用完全不同的代码实现的恶意软件组件。通过监控源代码和编译后的代码，我们能够有效地发现新型恶意软件并追踪野外环境中现存恶意软件的演变情况。

[Diamorphine](https://github.com/m0nad/Diamorphine)是一个广为人知的Linux内核rootkit，它支持多个版本的Linux内核（2.6.x、3.x、4.x、5.x和6.x）和多种处理器架构（x86、x86\_64和ARM64）。简而言之，一旦加载，该模块就会变得隐蔽，隐藏所有攻击者在编译时指定的特殊前缀开头的文件和文件夹。此后，攻击者可以通过发送信号与Diamorphine交互，执行如下操作：隐藏或显示任意进程，隐藏或显示内核模块，并提升权限至root用户。

在 2024 年 3 月初，我们发现了一种新的 Diamorphine 变种，在野外未被检测到。在获得样本后，我检查了.modinfo 部分，并注意到它伪装成合法的 x\_tables Netfilter 模块，并针对特定的内核版本（内核 5.19.17）进行了编译。

| ![image.png](images/attach-b56107de445dc79f945c1e96bbf8d553340c0284.png) |
|---|
| 图1：.modinfo信息 |

通过Radare2分析工具列出的函数，我们可以发现所分析的恶意软件样本中包含了Diamorphine,例如module\_hide、hacked\_kill、get\_syscall\_table\_bf、find\_task、is\_invisible和module\_show等函数。此外，模块中还包含了其他函数（如a、b、c、d、e、f和setup），表明该样本已经被武器化，具有更多的有效载荷。

| ![image.png](images/attach-d006f2b5e1e73d0183a911275bb49ac3a643d9af.png) |
|---|
| 图2：Radare2分析工具列出的函数信息 |

由于Diamorphine是一个广为人知的开源Linux内核rootkit，本博客文章将重点介绍其新增的功能：

- 通过向暴露的设备发送特定消息来终止Diamorphine的运行：这种消息被称为“xx\_tables”，是一种特殊的指令集。
- 利用所谓的“魔法数据包”来执行任意操作系统命令，这些数据包是精心设计以远程操控受感染系统的特殊信息包。

部署Diamorphine内核rootkit
======================

要部署这个Diamorphine的变种，我们需要一个内核版本为5.19.17的Linux操作系统。通过使用Radare2工具，我们可以找到合适的Linux发行版。根据编译器信息，Ubuntu 22.04版本是部署这个rootkit的理想选择。

| ![image.png](images/attach-cb83356ad47dd306a11e96b8c6079b0f88578ddf.png) |
|---|
| 图3：Ubuntu 22.04 |

实际上，我在网上发现有人使用Ubuntu Jammy版本来运行这个程序，而且这种特定Diamorphine恶意软件源代码中的符号版本，部分与我们在VirusTotal上发现的新Diamorphine变体中的符号版本相匹配（例如，module\_layout符号与版本不符，但unregister\_kprobe符号与之匹配）。

| ![image.png](images/attach-23bcde39989c39bc497cd5ed6f5997fe2010f871.png) |
|---|
| 图4：变体中的符号版本 |

因此，当Ubuntu Jammy（即Ubuntu 22.04 LTS版本）发行版具有合适版本的内核符号时，就可以将内核rootkit插入其中（具体符号版本信息可参见内核的[Module.symvers](https://www.kernel.org/doc/html/latest/kbuild/modules.html)文件，这是Diamorphine变种将要插入的位置）。

XX\_Tables：rootkit创建的用于用户空间和内核空间通信的设备。
======================================

模仿Netfilter的[X\_Tables](https://www.kernelconfig.io/config_netfilter_xtables)模块是一个巧妙的策略，因为这样做的话，注册Netfilter钩子不会引发警觉，毕竟与Netfilter的交互是正常行为。

在内核模块的初始化函数init\_module中，rootkit创建了一个名为xx\_tables的设备，用于在用户空间和内核模式的rootkit之间传递信息。

| ![image.png](images/attach-de1acc8c454fffbef494de99f9ca1baf3af35b28.png) |
|---|
| 图5：xx\_tables设备 |

秉承Linux系统中“一切皆文件”的设计哲学，字符设备在初始化时会设置一个文件操作结构，该结构定义了xx\_tables设备所支持的操作。在文件操作结构中定义的“g”函数，专门用来处理用户空间向设备写入数据的请求。

| ![image.png](images/attach-3b15c8e3f4cf7d16d06335737a70291cbd9dfe1c.png) |
|---|
| 图6 |

处理设备写入操作的“g”函数。
===============

该函数通过xx\_tables设备，从用户程序所在的内存区域读取命令。它使用Linux内核提供的`_copy_from_user`函数，将数据安全地从用户空间复制到内核空间。

| ![image.png](images/attach-ce206c607b10bd861d4119321cd0cf6224181154.png) |
|---|
| 图7 |

![image.png](images/attach-da0ddd3cbfb78dd96da7c61072c252bbc4b31f01.png)

为了确保安全，rootkit 会验证从用户程序运行的内存区域发送的数据是否为空。这个数据结构包括两个部分：数据的长度和指向数据位置的指针。

| ![image.png](images/attach-3b1c263d9e2e7383c1a3c0eff953dbce2e06b41b.png) |
|---|
| 图8 |

最后，如果从用户模式空间发送的输入是字符串“exit”，则调用 rootkit 的 `exit_` 函数，该函数将恢复系统、释放资源并从内存中卸载内核模块。

| ![image.png](images/attach-37c95394ad5a52546fb03c7d7bda0265e263124c.png) |
|---|
| 图9 |

`exit_`函数
=========

退出函数负责正确地恢复系统并从内核内存中卸载rootkit。它执行以下操作：

1. 销毁rootkit创建的设备。
2. 销毁用于创建设备的数据结构类。
3. 删除创建的字符设备。
4. 注销字符设备的注册区域。
5. 注销实现“魔法数据包”功能的Netfilter钩子。
6. 最后，它将系统调用表中的指针还原为原始函数。

魔术数据包
=====

新的Diamorphine rootkit实现了支持IPv4和IPv6的“魔术数据包”功能。协议族被设置为NFPROTO\_INET，这意味着它适用于IPv4和IPv6网络协议。

| ![image.png](images/attach-211d6525838308fe34bee7697615b3e726dc8c64.png) |
|---|
| 图10 |

netfilter\_hook\_function 依赖于对 a、b、c、d、e 和 f 函数的嵌套调用，用于处理魔术数据包。魔术数据包的要求包括使用 XOR 密钥 0x64 加密值 "`whitehat`" 和 "`2023_mn`"。

| ![image.png](images/attach-85822ec39618e086aaeb759c3986537339a01f5b.png) |
|---|
| 图11 |

如果数据包符合要求，则从中提取任意命令并执行到受感染的计算机中。

| ![image.png](images/attach-f2812bb0028418e8790c69a7dbd91d5e27064c1a.png) |
|---|
| 图12 |

系统调用中的hook
==========

Diamorphine rootkit的原始系统调用拦截实现是这样的：

| ![image.png](images/attach-a3d119c113050053e00b78b21095d0c19c3751d6.png) |
|---|
| 图13 |

即便是在新的Diamorphine变种中代码完全相同，也需要指出它被特别配置来隐藏所有包含特定字符串的文件和文件夹。

| ![image.png](images/attach-672d55d7904586879defdec786800ba8f42328ad.png) |
|---|
| 图14 |

结论
==

我们经常发现新的Linux内核rootkit实现了未被检测到的魔术数据包（例如[Syslogk](https://decoded.avast.io/davidalvarez/linux-threat-hunting-syslogk-a-kernel-rootkit-found-under-development-in-the-wild/)、[AntiUnhide](https://www.virustotal.com/gui/file/D6E74832BBABCA012BC0C3A8A5F1A87CB4B5D241E2A88B75CB01CB0E076B8C98)、[Chicken](https://www.virustotal.com/gui/file/2d4353232fb36aed5440fdc5b763bfa273f9cd3c9dbf392aaed1e3ba66bb429c/detection/f-2d4353232fb36aed5440fdc5b763bfa273f9cd3c9dbf392aaed1e3ba66bb429c-1691657203)等)

| ![image.png](images/attach-348b93598e0dd84882c0c9d2f5a27ab53fa5f42c.png) |
|---|
| 图15 |

在这个新的Diamorphine野外版本中，威胁行为者增加了一项设备功能，允许从内存中卸载rootkit内核模块，并且增加了魔术数据包功能，使得在受感染系统中执行任意命令成为可能。

如何防止感染并保持网络安全（有修改）
==================

1. 定期更新您的操作系统和应用软件到最新版本。
2. 确保您的网络连接是安全的，例如使用虚拟私人网络（VPN）来加密您的在线活动。
3. 不要从不可靠的来源下载或执行文件，以避免潜在的安全风险。
4. 遵循最小权限原则，尤其是在Linux系统中，除非确实必要，不要使用root账户进行操作。
5. 安装并使用知名的网络安全软件，如卡巴斯基、360、火绒，以确保您的设备免受恶意软件的侵害。
6. 安装未知软件时先上传到virustotal看看

新的Diamorphine变种
===============

```html
067194bb1a70e9a3d18a6e4252e9a9c881ace13a6a3b741e9f0ec299451c2090
```

IoC
===

Diamorphine Linux内核rootkit IoC、Yara 搜寻规则和 VirusTotal 查询位于我们的 IoC 存储库中。

```html
https://github.com/avast/ioc/tree/master/Diamorphine
```
