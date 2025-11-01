# 一次Telegram窃取程序的深入解析：从技术细节到定位攻击者账户的完整流程-先知社区

> **来源**: https://xz.aliyun.com/news/16007  
> **文章ID**: 16007

---

![](images/20241206115246-8e305eea-b385-1.png)  
32位程序，并且是一个.net文件

![](images/20241206115257-94b0b18e-b385-1.png)  
用dnspy分析，直接定位到主函数

![](images/20241206115315-9ef1ca84-b385-1.png)  
恶意软件从程序集的 AssemblyDescription 属性中提取配置信息，进行base64解码，关键的 Telegram Token 和 Chat ID进行了rot13加密

![](images/20241206115327-a68ce6b6-b385-1.png)

调用 persistence.CheckCopy()，确保恶意程序被复制到目标路径，防止被删除

![](images/20241206115339-ad905420-b385-1.png)

![](images/20241206115344-b0b5a4b6-b385-1.png)  
在注册表中创建键值，并在发现相同键值存在时停止运行，确保只有一个实例运行

![](images/20241206115354-b6b40c54-b385-1.png)  
检测是否在虚拟机、沙箱等分析环境中运行。如果检测到分析环境，则退出程序

![](images/20241206115406-bdc47d08-b385-1.png)  
窃取浏览器的敏感数据，包括保存的密码、cookies 和自动填充信息

![](images/20241206115424-c86d4230-b385-1.png)  
窃取被害者主机上的telegram数据，复制数据并压缩为 ZIP 文件，通过 Telegram API 发送到攻击者的服务器

![](images/20241206115437-d026546c-b385-1.png)

![](images/20241206115441-d26ef2f6-b385-1.png)  
窃取被害者主机上的Exodus 钱包数据，复制数据并压缩为 ZIP 文件，通过 Telegram API 发送到攻击者的服务器

![](images/20241206115451-d861e704-b385-1.png)

![](images/20241206115458-dccb05fa-b385-1.png)

窃取被害者主机上的Metamask数据，复制数据并压缩为 ZIP 文件，通过 Telegram API 发送到攻击者的服务器

![](images/20241206115509-e31c855a-b385-1.png)  
获取被害者主机上的系统和硬件信息，包括CPU、GPU、RAM以及系统版本，然后保存到Log\ComputerInfo.txt中

![](images/20241206115521-ea55b22e-b385-1.png)

![](images/20241206115526-ed7d925a-b385-1.png)  
调用 utils 模块的 desktopScreenshot() 函数截取受害者的桌面截图，最后将所有窃取的数据压缩为 ZIP 文件，通过 Telegram Bot API 上传到攻击者的 Telegram 账户

![](images/20241206115558-0045423e-b386-1.png)

发送文件后会删除痕迹，包括压缩的zip文件和恶意程序自己

![](images/20241206115549-fab8fbee-b385-1.png)

![](images/20241206115606-0528b0f6-b386-1.png)

# 定位攻击者github账户

在config数据里找到了攻击者的github主页

![](images/20241206115625-10780d3a-b386-1.png)

```
https://github.com/attatier
```

![](images/20241206115640-193f833a-b386-1.png)  
查看攻击者创建的项目，在历史记录里可以找到恶意程序的传播方式

![](images/20241206115707-29831482-b386-1.png)  
是一个快捷文件，直接用lnkparse分析

![](images/20241206115719-30d8fada-b386-1.png)  
快捷文件直接调用powershell远程获取恶意软件，在被害者主机上运行

![](images/20241206115734-39865092-b386-1.png)

![](images/20241206115739-3c6633cc-b386-1.png)  
然后远程获取正常pdf文件，并在被害者执行程序后自动打开，伪装自己

![](images/20241206115747-417db240-b386-1.png)

# 定位攻击者telegram账户

![](images/20241206115821-555a7a1e-b386-1.png)

截取流量

![](images/20241206115827-596d5c20-b386-1.png)

![](images/20241206115832-5bfb8548-b386-1.png)  
telegram账户：

```
7781867830
```

生命周期：

![](images/20241206120107-b879a444-b386-1.png)  
信息：

```
hash:
50a6880b7a2cfb41d50b9fa34438b8fa
4bc209d3c71283fd0efefe10ef2bc4387dd26c19

攻击者账户：
https://github.com/attatier
telegram id：7781867830
```
