# 记一次DarkCrystal木马投毒分析-先知社区

> **来源**: https://xz.aliyun.com/news/17877  
> **文章ID**: 17877

---

# 前言

拿到了一个样本，经过后续的分析发现为DarkCrystal RAT，攻击者使用了多种技术手法，本文将进行详细分析。

# 初始样本

初始样本名为 Solara.exe，Solara实际是一个脚本编辑器，攻击者通过伪装成Solara进行投毒，这里的Solara样本为一个.NET的dropper。会根据硬编码的规则，将资源中的四个文件释放到指定目录并运行。

![1.png](images/img_17877_000.png)

其中四个文件的功能描述如下

|  |  |
| --- | --- |
| 文件名 | 功能描述 |
| deldef.exe | 执行硬编码的powershell命令 |
| Solara.exe | 合法的Solara安装程序 |
| main.exe | winrar自解压程序，释放恶意文件 |
| Loader.exe | 远程下载r77rootkit |

# 文件deldef.exe

该文件使用了开源项目 <https://github.com/MScholtes/PS2EXE> 将powrshell命令转为.NET程序来运行。 尝试关闭并禁用windows defender，并关闭UAC。![2.png](images/img_17877_001.png)![3.png](images/img_17877_002.png)

# 文件Solara.exe

实际上真正的Solara安装程序，会执行安装操作。  
![4.png](images/img_17877_003.png)

# 文件Loader.exe

Loader.exe为一个经过.NET Reactor高度混淆后的样本  
![5.png](images/img_17877_004.png)

这里使用开源的 <https://github.com/SychicBoy/NETReactorSlayer> 进行反混淆  
![6.png](images/img_17877_005.png)

反混淆后，程序逻辑较为简单，攻击者将恶意文件托管在github上面，下载保存在用户临时目录并运行。![7.png](images/img_17877_006.png)

继续分析Install.exe，发现其为开源的 R3 rootkit <https://github.com/bytecode77/r77-rootkit> ![8.png](images/img_17877_007.png)![9.png](images/img_17877_008.png)

该rootkit，采用反射性dll注入，通过hook 关键nt函数，来实现隐藏进程，文件，目录，注册表等功能。![8_1.png](images/img_17877_009.png)

# 文件main.exe

该文件为winrar自解压程序，同样也是一个dropper。![10.png](images/img_17877_010.png)

会将上述文件释放到目录 C:$77Containerinto下，并运行 QGprn9qddWdIFanzSGPE1hxX8TjAJ8MC3Tf2Jcl2MKzC0VjU7.vbe 脚本![11.png](images/img_17877_011.png)![12.png](images/img_17877_012.png)

其中的vbe脚本，是一个加密脚本，可将其解密为正常的vbs脚本 <https://github.com/JohnHammond/vbe-decoder/blob/master/vbe-decoder.py> 。脚本实际功能为运行另外一个bat脚本。  
![12_1.png](images/img_17877_013.png)

bat脚本为运行最后的DarkCrystal木马。  
![12_2.png](images/img_17877_014.png)

# DarkCrystal本体分析

$77Serverreview.exe，为.NET编写的DarkCrystal木马，该样本同样也为经过.NET Reactor高度混淆后的样本。  
![13.png](images/img_17877_015.png)

反混淆后，进行分析，发现DarkCrystal标志性格式的互斥字符串。![14.png](images/img_17877_016.png)

部分配置经过多层编码，解码后如下![15.png](images/img_17877_017.png)

收集当前主机敏感信息，包括 主机名，用户名，是否管理员权限运行，是否存在麦克风，是否存在摄像头，CPU，GPU，活动窗口等信息。![16.png](images/img_17877_018.png)

收集应用软件信息，包括telegram，steam，discord等![24.png](images/img_17877_019.png)

获取剪贴板信息![22.png](images/img_17877_020.png)

获取屏幕截图![20.png](images/img_17877_021.png)

获取大量系统信息![21.png](images/img_17877_022.png)

通讯C2地址![17.png](images/img_17877_023.png)

反射执行插件![23.png](images/img_17877_024.png)

DarkCrystal还有一个伪装功能，遍历系统正在运行的进程，将一个木马的名称改为与被选择的进程相同，然后复制到指定目录，并将选中的进程结束后追加后缀.exe。然后将复制后的木马添加到自启动。![18.png](images/img_17877_025.png)![19.png](images/img_17877_026.png)

# 总结

该样本相对较为复杂，且使用了混淆加密手段和rootkit技术。下载软件时要仔细辨别是否为官网，并检查数字签名是否有效，避免沦为攻击者的"肉鸡"。

# IOC

http://micrepnis[.]ru/pollWpdownloadstemporary.php
